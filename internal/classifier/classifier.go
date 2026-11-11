// Package classifier categorizes Synapse rooms into bridge/orphan, federated, single-user notes, and local Room v12 candidates.
package classifier

import (
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
)

// RoomCategory labels the classification outcome for an exported Synapse room.
type RoomCategory string

// Classification buckets produced by inspecting room state and membership history.
const (
	CategoryBridgeOrOrphan RoomCategory = "bridge_or_orphan"
	CategoryFederated      RoomCategory = "federated"
	CategorySingleUserNote RoomCategory = "single_user_notes"
	CategoryLocalRoom      RoomCategory = "local_room"
)

const (
	roomVersionTwelve       = "12"
	roomTypeSpace           = "m.space"
	membershipJoin          = "join"
	adminPowerThreshold     = 100
	defaultStatePowerLevel  = 50
	defaultActionPowerLevel = 50
	eventTypeCreate         = "m.room.create"
	eventTypeMember         = "m.room.member"
	eventTypePowerLevels    = "m.room.power_levels"
	eventTypeName           = "m.room.name"
	eventTypeTopic          = "m.room.topic"
	eventTypeAvatar         = "m.room.avatar"
	eventTypeEncryption     = "m.room.encryption"
	eventTypeRetention      = "m.room.retention"
	eventTypeHistoryVis     = "m.room.history_visibility"
	eventTypeJoinRules      = "m.room.join_rules"
	eventTypeGuestAccess    = "m.room.guest_access"
	eventTypeSpaceChild     = "m.space.child"
	eventTypeBridge         = "m.bridge"
	eventTypeHalfShotBridge = "uk.half-shot.bridge"
	eventTypeFuncMembers    = "io.element.functional_members"
	prefixMauBridge         = "fi.mau."
)

// StateEvent represents a raw Matrix room state event retrieved from Synapse.
type StateEvent struct {
	Type     string          `json:"type"`
	StateKey string          `json:"state_key"`
	Sender   string          `json:"sender"`
	Content  json.RawMessage `json:"content"`
}

// RoomObservation aggregates a single room's state and all allowlisted local users joined to it.
type RoomObservation struct {
	RoomID           string
	AvatarSHA256     string
	AvatarType       string
	AvatarMXC        string
	JoinedLocalUsers []string
	StateEvents      []StateEvent
	AvatarSize       int64
}

// ClassifiedRoom captures the deterministic classification category and optional local or federated output.
type ClassifiedRoom struct {
	Local                    *dump.LocalRoom
	Federated                *dump.FederatedRoom
	Category                 RoomCategory
	RoomID                   string
	RoomName                 string
	SkipReason               string
	BridgeUsers              []string
	ExcludedJoinedLocalUsers []string
	DepartedLocalUsers       []string
	DepartedExternalUsers    []string
}

// ExcludedRoom preserves diagnostic context explaining why a room was omitted from Tuwunel migration.
type ExcludedRoom struct {
	RoomID                   string
	RoomName                 string
	Reason                   string
	BridgeUsers              []string
	JoinedLocalUsers         []string
	ExcludedJoinedLocalUsers []string
	DepartedLocalUsers       []string
	DepartedExternalUsers    []string
}

// PartialLocalRoom preserves diagnostic context for local rooms migrated after dropping excluded or departed participants.
type PartialLocalRoom struct {
	RoomID                   string
	RoomName                 string
	JoinedLocalUsers         []string
	ExcludedJoinedLocalUsers []string
	DepartedLocalUsers       []string
	DepartedExternalUsers    []string
}

// Corpus holds the deduplicated output of classifying all observed Synapse rooms.
type Corpus struct {
	BridgeOrOrphanRooms map[string]struct{}
	BridgeOrphanReasons map[string]string
	ExcludedRooms       []ExcludedRoom
	PartialLocalRooms   []PartialLocalRoom
	FederatedRooms      []dump.FederatedRoom
	LocalRooms          []dump.LocalRoom
}

// ClassifyOptions controls room version target and direct-room detection hints during classification.
type ClassifyOptions struct {
	AllowlistedUsers map[string]struct{}
	DirectRoomIDs    map[string]struct{}
	ServerName       string
	LocalRoomVersion string
}

type memberContent struct {
	Membership string `json:"membership"`
}

type createContent struct {
	Creator string `json:"creator"`
	Type    string `json:"type"`
}

type functionalMembersContent struct {
	ServiceMembers []string `json:"service_members"`
}

type powerLevelsRaw struct {
	Users         map[string]int `json:"users"`
	Events        map[string]int `json:"events"`
	Notifications map[string]int `json:"notifications"`
	UsersDefault  *int           `json:"users_default"`
	EventsDefault *int           `json:"events_default"`
	StateDefault  *int           `json:"state_default"`
	Ban           *int           `json:"ban"`
	Kick          *int           `json:"kick"`
	Redact        *int           `json:"redact"`
	Invite        *int           `json:"invite"`
}

type textContent struct {
	Name              string `json:"name"`
	Topic             string `json:"topic"`
	HistoryVisibility string `json:"history_visibility"`
	JoinRule          string `json:"join_rule"`
	GuestAccess       string `json:"guest_access"`
}

type encryptionRaw struct {
	Algorithm            string `json:"algorithm"`
	RotationPeriodMillis int64  `json:"rotation_period_ms"`
	RotationPeriodMsgs   int    `json:"rotation_period_msgs"`
}

type retentionRaw struct {
	MaxLifetime *int64 `json:"max_lifetime"`
	MinLifetime *int64 `json:"min_lifetime"`
}

type spaceChildRaw struct {
	Order     string   `json:"order"`
	Via       []string `json:"via"`
	Suggested bool     `json:"suggested"`
}

type domainStats struct {
	maxPower int
	count    int
}

type memberAnalysis struct {
	joinedExternal        []string
	departedExternal      []string
	excludedJoinedLocal   []string
	departedLocal         []string
	hasDepartedAllowLocal bool
}

// ClassifyCorpus deduplicates observations by room ID, classifies every room, and prunes bridge links and empty Spaces.
func ClassifyCorpus(observations []RoomObservation, opts ClassifyOptions) Corpus {
	localRoomVersion := strings.TrimSpace(opts.LocalRoomVersion)
	if localRoomVersion == "" {
		localRoomVersion = roomVersionTwelve
	}
	opts.LocalRoomVersion = localRoomVersion

	dedup := deduplicateObservations(observations)

	roomIDs := make([]string, 0, len(dedup))
	for roomID := range dedup {
		roomIDs = append(roomIDs, roomID)
	}
	sort.Strings(roomIDs)

	corpus := Corpus{
		BridgeOrOrphanRooms: make(map[string]struct{}),
		BridgeOrphanReasons: make(map[string]string),
	}

	partialByRoom := make(map[string]PartialLocalRoom)
	for _, roomID := range roomIDs {
		obs := dedup[roomID]
		res := ClassifyRoom(&obs, opts)
		switch res.Category {
		case CategoryBridgeOrOrphan:
			corpus.BridgeOrOrphanRooms[roomID] = struct{}{}
			corpus.BridgeOrphanReasons[roomID] = res.SkipReason
			corpus.ExcludedRooms = append(corpus.ExcludedRooms, ExcludedRoom{
				RoomID:                   roomID,
				RoomName:                 res.RoomName,
				Reason:                   res.SkipReason,
				BridgeUsers:              slices.Clone(res.BridgeUsers),
				JoinedLocalUsers:         slices.Clone(obs.JoinedLocalUsers),
				ExcludedJoinedLocalUsers: slices.Clone(res.ExcludedJoinedLocalUsers),
				DepartedLocalUsers:       slices.Clone(res.DepartedLocalUsers),
				DepartedExternalUsers:    slices.Clone(res.DepartedExternalUsers),
			})
		case CategoryFederated:
			corpus.FederatedRooms = append(corpus.FederatedRooms, *res.Federated)
		case CategorySingleUserNote, CategoryLocalRoom:
			corpus.LocalRooms = append(corpus.LocalRooms, *res.Local)
			if len(res.ExcludedJoinedLocalUsers) > 0 || len(res.DepartedLocalUsers) > 0 || len(res.DepartedExternalUsers) > 0 {
				partialByRoom[roomID] = PartialLocalRoom{
					RoomID:                   roomID,
					RoomName:                 res.RoomName,
					JoinedLocalUsers:         slices.Clone(res.Local.JoinedMembers),
					ExcludedJoinedLocalUsers: slices.Clone(res.ExcludedJoinedLocalUsers),
					DepartedLocalUsers:       slices.Clone(res.DepartedLocalUsers),
					DepartedExternalUsers:    slices.Clone(res.DepartedExternalUsers),
				}
			}
		}
	}

	pruneEmptyAndBridgeSpaces(&corpus, partialByRoom)
	collectPartialLocalRooms(&corpus, partialByRoom)
	return corpus
}

func deduplicateObservations(observations []RoomObservation) map[string]RoomObservation {
	dedup := make(map[string]RoomObservation, len(observations))
	for _, obs := range observations {
		existing, ok := dedup[obs.RoomID]
		if !ok {
			obs.JoinedLocalUsers = dedupeSorted(obs.JoinedLocalUsers)
			dedup[obs.RoomID] = obs
			continue
		}
		combined := append(slices.Clone(existing.JoinedLocalUsers), obs.JoinedLocalUsers...)
		existing.JoinedLocalUsers = dedupeSorted(combined)
		if len(existing.StateEvents) == 0 && len(obs.StateEvents) > 0 {
			existing.StateEvents = obs.StateEvents
		}
		if existing.AvatarSHA256 == "" && obs.AvatarSHA256 != "" {
			existing.AvatarSHA256 = obs.AvatarSHA256
			existing.AvatarType = obs.AvatarType
			existing.AvatarMXC = obs.AvatarMXC
			existing.AvatarSize = obs.AvatarSize
		}
		dedup[obs.RoomID] = existing
	}
	return dedup
}

// ClassifyRoom deterministically classifies a single Synapse room from its full state and membership events.
func ClassifyRoom(obs *RoomObservation, opts ClassifyOptions) ClassifiedRoom {
	parsed := parseStateEvents(obs.StateEvents, opts)
	members := analyzeMembers(parsed.members, opts)

	if parsed.hasBridgeMarker {
		return ClassifiedRoom{
			Category:                 CategoryBridgeOrOrphan,
			RoomID:                   obs.RoomID,
			RoomName:                 parsed.name,
			SkipReason:               parsed.bridgeReason,
			BridgeUsers:              dedupeSorted(parsed.bridgeUsers),
			ExcludedJoinedLocalUsers: members.excludedJoinedLocal,
			DepartedLocalUsers:       members.departedLocal,
			DepartedExternalUsers:    members.departedExternal,
		}
	}

	if len(members.joinedExternal) > 0 {
		return ClassifiedRoom{
			Category: CategoryFederated,
			RoomID:   obs.RoomID,
			Federated: &dump.FederatedRoom{
				RoomID:           obs.RoomID,
				JoinedLocalUsers: dedupeSorted(obs.JoinedLocalUsers),
				ViaServers:       rankViaServers(members.joinedExternal, parsed.powerLevels),
			},
		}
	}

	joinedLocal := dedupeSorted(obs.JoinedLocalUsers)
	if len(joinedLocal) == 0 {
		return ClassifiedRoom{
			Category:                 CategoryBridgeOrOrphan,
			RoomID:                   obs.RoomID,
			RoomName:                 parsed.name,
			SkipReason:               "no allowlisted local member is currently joined",
			ExcludedJoinedLocalUsers: members.excludedJoinedLocal,
			DepartedLocalUsers:       members.departedLocal,
			DepartedExternalUsers:    members.departedExternal,
		}
	}

	if parsed.roomType == roomTypeSpace {
		return classifyLocalSpace(obs, &parsed, &members, joinedLocal, opts)
	}

	if len(joinedLocal) == 1 {
		return classifySingleJoinedLocalRoom(obs, &parsed, &members, joinedLocal, opts)
	}

	localRoom := buildLocalRoom(obs, &parsed, joinedLocal, dump.RoomCategoryLocal, opts)
	return ClassifiedRoom{
		Category:                 CategoryLocalRoom,
		RoomID:                   obs.RoomID,
		RoomName:                 parsed.name,
		Local:                    &localRoom,
		ExcludedJoinedLocalUsers: members.excludedJoinedLocal,
		DepartedLocalUsers:       members.departedLocal,
		DepartedExternalUsers:    members.departedExternal,
	}
}

func classifyLocalSpace(
	obs *RoomObservation,
	parsed *parsedRoomState,
	members *memberAnalysis,
	joinedLocal []string,
	opts ClassifyOptions,
) ClassifiedRoom {
	if len(parsed.spaceChildren) == 0 {
		return ClassifiedRoom{
			Category:                 CategoryBridgeOrOrphan,
			RoomID:                   obs.RoomID,
			RoomName:                 parsed.name,
			SkipReason:               "space contains no child rooms",
			ExcludedJoinedLocalUsers: members.excludedJoinedLocal,
			DepartedLocalUsers:       members.departedLocal,
			DepartedExternalUsers:    members.departedExternal,
		}
	}
	localRoom := buildLocalRoom(obs, parsed, joinedLocal, dump.RoomCategoryLocal, opts)
	return ClassifiedRoom{
		Category:                 CategoryLocalRoom,
		RoomID:                   obs.RoomID,
		RoomName:                 parsed.name,
		Local:                    &localRoom,
		ExcludedJoinedLocalUsers: members.excludedJoinedLocal,
		DepartedLocalUsers:       members.departedLocal,
		DepartedExternalUsers:    members.departedExternal,
	}
}

func classifySingleJoinedLocalRoom(
	obs *RoomObservation,
	parsed *parsedRoomState,
	members *memberAnalysis,
	joinedLocal []string,
	opts ClassifyOptions,
) ClassifiedRoom {
	if hasNonSingleMembers(parsed, members) {
		return ClassifiedRoom{
			Category:                 CategoryBridgeOrOrphan,
			RoomID:                   obs.RoomID,
			RoomName:                 parsed.name,
			SkipReason:               singleLocalExclusionReason(members),
			ExcludedJoinedLocalUsers: members.excludedJoinedLocal,
			DepartedLocalUsers:       members.departedLocal,
			DepartedExternalUsers:    members.departedExternal,
		}
	}
	category := CategoryLocalRoom
	localCategoryStr := dump.RoomCategoryLocal
	if len(parsed.members) == 1 {
		category = CategorySingleUserNote
		localCategoryStr = dump.RoomCategoryNotes
	}
	localRoom := buildLocalRoom(obs, parsed, joinedLocal, localCategoryStr, opts)
	return ClassifiedRoom{
		Category: category,
		RoomID:   obs.RoomID,
		RoomName: parsed.name,
		Local:    &localRoom,
	}
}

func hasNonSingleMembers(parsed *parsedRoomState, members *memberAnalysis) bool {
	return len(members.excludedJoinedLocal) > 0 ||
		len(members.departedLocal) > 0 ||
		len(members.departedExternal) > 0 ||
		members.hasDepartedAllowLocal ||
		len(parsed.members) > 1
}

func singleLocalExclusionReason(members *memberAnalysis) string {
	hasExcludedLocal := len(members.excludedJoinedLocal) > 0 || len(members.departedLocal) > 0
	hasDepartedExternal := len(members.departedExternal) > 0
	switch {
	case hasExcludedLocal && hasDepartedExternal:
		return "only 1 allowlisted local member remains after excluding non-allowlisted local and departed external participants"
	case hasExcludedLocal:
		return "only 1 allowlisted local member remains after excluding non-allowlisted local participants"
	case hasDepartedExternal:
		return "only 1 allowlisted local member remains because all external federated members have departed"
	default:
		return "only 1 allowlisted local member remains because all other allowlisted local members have departed"
	}
}

type parsedRoomState struct {
	members           map[string]string
	powerLevels       *powerLevelsRaw
	encryption        *dump.EncryptionConfig
	retention         *dump.RetentionConfig
	bridgeReason      string
	roomType          string
	originalCreator   string
	name              string
	topic             string
	historyVisibility string
	joinRule          string
	guestAccess       string
	spaceChildren     []dump.SpaceChildEntry
	bridgeUsers       []string
	hasBridgeMarker   bool
}

func parseStateEvents(events []StateEvent, opts ClassifyOptions) parsedRoomState {
	state := parsedRoomState{
		members: make(map[string]string),
	}
	var explicitBridgeEvent string
	for _, ev := range events {
		isExplicitBridge, blocked := inspectBridgeStateEvent(&ev, opts.AllowlistedUsers)
		if isExplicitBridge {
			state.hasBridgeMarker = true
			if explicitBridgeEvent == "" {
				explicitBridgeEvent = ev.Type
			}
		} else if len(blocked) > 0 {
			state.hasBridgeMarker = true
			state.bridgeUsers = append(state.bridgeUsers, blocked...)
		}
		applyStateEvent(&state, &ev)
	}
	if state.hasBridgeMarker {
		state.bridgeReason = buildBridgeReason(explicitBridgeEvent)
	}
	return state
}

func buildBridgeReason(explicitBridgeEvent string) string {
	if explicitBridgeEvent != "" {
		return "room is linked to a bridge via " + explicitBridgeEvent + " state event"
	}
	return "room contains non-allowlisted functional service members (io.element.functional_members)"
}

func applyStateEvent(state *parsedRoomState, ev *StateEvent) {
	if applyRoomTextState(state, ev) {
		return
	}
	switch ev.Type {
	case eventTypeCreate:
		state.originalCreator = ev.Sender
		var cc createContent
		if json.Unmarshal(ev.Content, &cc) == nil {
			state.roomType = cc.Type
			if state.originalCreator == "" {
				state.originalCreator = cc.Creator
			}
		}
	case eventTypeMember:
		var mc memberContent
		if json.Unmarshal(ev.Content, &mc) == nil && ev.StateKey != "" {
			state.members[ev.StateKey] = mc.Membership
		}
	case eventTypePowerLevels:
		var pl powerLevelsRaw
		if json.Unmarshal(ev.Content, &pl) == nil {
			state.powerLevels = &pl
		}
	case eventTypeEncryption:
		applyEncryptionState(state, ev)
	case eventTypeRetention:
		applyRetentionState(state, ev)
	case eventTypeSpaceChild:
		applySpaceChildState(state, ev)
	}
}

func applyRoomTextState(state *parsedRoomState, ev *StateEvent) bool {
	var tc textContent
	switch ev.Type {
	case eventTypeName:
		if json.Unmarshal(ev.Content, &tc) == nil {
			state.name = tc.Name
		}
	case eventTypeTopic:
		if json.Unmarshal(ev.Content, &tc) == nil {
			state.topic = tc.Topic
		}
	case eventTypeHistoryVis:
		if json.Unmarshal(ev.Content, &tc) == nil {
			state.historyVisibility = tc.HistoryVisibility
		}
	case eventTypeJoinRules:
		if json.Unmarshal(ev.Content, &tc) == nil {
			state.joinRule = tc.JoinRule
		}
	case eventTypeGuestAccess:
		if json.Unmarshal(ev.Content, &tc) == nil {
			state.guestAccess = tc.GuestAccess
		}
	default:
		return false
	}
	return true
}

func applyEncryptionState(state *parsedRoomState, ev *StateEvent) {
	var er encryptionRaw
	if json.Unmarshal(ev.Content, &er) == nil && er.Algorithm != "" {
		state.encryption = &dump.EncryptionConfig{
			Algorithm:            er.Algorithm,
			RotationPeriodMillis: er.RotationPeriodMillis,
			RotationPeriodMsgs:   er.RotationPeriodMsgs,
		}
	}
}

func applyRetentionState(state *parsedRoomState, ev *StateEvent) {
	var rr retentionRaw
	if json.Unmarshal(ev.Content, &rr) == nil && (rr.MaxLifetime != nil || rr.MinLifetime != nil) {
		state.retention = &dump.RetentionConfig{
			MaxLifetime: rr.MaxLifetime,
			MinLifetime: rr.MinLifetime,
		}
	}
}

func applySpaceChildState(state *parsedRoomState, ev *StateEvent) {
	if ev.StateKey == "" {
		return
	}
	var sc spaceChildRaw
	if json.Unmarshal(ev.Content, &sc) == nil && len(sc.Via) > 0 {
		state.spaceChildren = append(state.spaceChildren, dump.SpaceChildEntry{
			ChildRoomID: ev.StateKey,
			Order:       sc.Order,
			Via:         dedupeSorted(sc.Via),
			Suggested:   sc.Suggested,
		})
	}
}

func inspectBridgeStateEvent(ev *StateEvent, allowlisted map[string]struct{}) (isExplicitBridge bool, blockedServiceUsers []string) {
	if ev.Type == eventTypeBridge || ev.Type == eventTypeHalfShotBridge || strings.HasPrefix(ev.Type, prefixMauBridge) {
		return true, nil
	}
	if ev.Type != eventTypeFuncMembers {
		return false, nil
	}
	var fm functionalMembersContent
	if json.Unmarshal(ev.Content, &fm) != nil {
		return false, nil
	}
	var blocked []string
	for _, member := range fm.ServiceMembers {
		if _, ok := allowlisted[member]; !ok {
			blocked = append(blocked, member)
		}
	}
	return false, blocked
}

func analyzeMembers(members map[string]string, opts ClassifyOptions) memberAnalysis {
	var out memberAnalysis
	for userID, membership := range members {
		domain := extractServerName(userID)
		if domain != opts.ServerName {
			if membership == membershipJoin {
				out.joinedExternal = append(out.joinedExternal, userID)
			} else {
				out.departedExternal = append(out.departedExternal, userID)
			}
			continue
		}
		if _, ok := opts.AllowlistedUsers[userID]; ok {
			if membership != membershipJoin {
				out.hasDepartedAllowLocal = true
			}
			continue
		}
		if membership == membershipJoin {
			out.excludedJoinedLocal = append(out.excludedJoinedLocal, userID)
		} else {
			out.departedLocal = append(out.departedLocal, userID)
		}
	}
	sort.Strings(out.joinedExternal)
	sort.Strings(out.departedExternal)
	sort.Strings(out.excludedJoinedLocal)
	sort.Strings(out.departedLocal)
	return out
}

func rankViaServers(joinedExternal []string, pl *powerLevelsRaw) []string {
	stats := make(map[string]domainStats)
	for _, userID := range joinedExternal {
		domain := extractServerName(userID)
		if domain == "" {
			continue
		}
		power := memberPowerLevel(userID, pl)
		cur, exists := stats[domain]
		if !exists {
			stats[domain] = domainStats{maxPower: power, count: 1}
			continue
		}
		if power > cur.maxPower {
			cur.maxPower = power
		}
		cur.count++
		stats[domain] = cur
	}

	domains := make([]string, 0, len(stats))
	for domain := range stats {
		domains = append(domains, domain)
	}
	sort.Slice(domains, func(i, j int) bool {
		a, b := stats[domains[i]], stats[domains[j]]
		if a.maxPower != b.maxPower {
			return a.maxPower > b.maxPower
		}
		if a.count != b.count {
			return a.count > b.count
		}
		return domains[i] < domains[j]
	})
	return domains
}

func buildLocalRoom(obs *RoomObservation, state *parsedRoomState, joinedLocal []string, categoryStr string, opts ClassifyOptions) dump.LocalRoom {
	chosenCreator := chooseCreator(state.originalCreator, joinedLocal, state.powerLevels)
	additionalCreators, transformedPL := TransformPowerLevels(state.powerLevels, chosenCreator, joinedLocal, opts.LocalRoomVersion)

	var avatarRef *dump.MediaRef
	if obs.AvatarSHA256 != "" {
		avatarRef = &dump.MediaRef{
			OriginalMXC: obs.AvatarMXC,
			SHA256:      obs.AvatarSHA256,
			ContentType: obs.AvatarType,
			Size:        obs.AvatarSize,
		}
	}

	sort.Slice(state.spaceChildren, func(i, j int) bool {
		return state.spaceChildren[i].ChildRoomID < state.spaceChildren[j].ChildRoomID
	})

	_, isDirectHint := opts.DirectRoomIDs[obs.RoomID]
	return dump.LocalRoom{
		OldRoomID:          obs.RoomID,
		Category:           categoryStr,
		RoomType:           state.roomType,
		OriginalCreator:    state.originalCreator,
		ChosenCreator:      chosenCreator,
		AdditionalCreators: additionalCreators,
		Name:               state.name,
		Topic:              state.topic,
		Avatar:             avatarRef,
		Encryption:         state.encryption,
		Retention:          state.retention,
		HistoryVisibility:  state.historyVisibility,
		JoinRule:           state.joinRule,
		GuestAccess:        state.guestAccess,
		PowerLevels:        transformedPL,
		JoinedMembers:      joinedLocal,
		SpaceChildren:      slices.Clone(state.spaceChildren),
		IsDirect:           isDirectHint && len(joinedLocal) == 2,
	}
}

func chooseCreator(originalCreator string, joinedLocal []string, pl *powerLevelsRaw) string {
	if slices.Contains(joinedLocal, originalCreator) {
		return originalCreator
	}
	best := joinedLocal[0]
	bestPower := memberPowerLevel(best, pl)
	for _, candidate := range joinedLocal[1:] {
		power := memberPowerLevel(candidate, pl)
		if power > bestPower {
			best = candidate
			bestPower = power
		}
	}
	return best
}

// TransformPowerLevels maps co-admins to v12 additional_creators and strips creators from power_levels.users.
func TransformPowerLevels(raw *powerLevelsRaw, chosenCreator string, joinedLocal []string, roomVersion string) ([]string, *dump.PowerLevelsConfig) {
	if raw == nil && roomVersion == roomVersionTwelve {
		return nil, nil
	}

	users := make(map[string]int)
	if raw != nil && raw.Users != nil {
		for _, member := range joinedLocal {
			if power, ok := raw.Users[member]; ok {
				users[member] = power
			}
		}
	}

	var additionalCreators []string
	if roomVersion == roomVersionTwelve {
		delete(users, chosenCreator)
		for _, member := range joinedLocal {
			if member == chosenCreator {
				continue
			}
			if power, ok := users[member]; ok && power >= adminPowerThreshold {
				additionalCreators = append(additionalCreators, member)
				delete(users, member)
			}
		}
		sort.Strings(additionalCreators)
	} else if _, ok := users[chosenCreator]; !ok {
		users[chosenCreator] = adminPowerThreshold
	}

	if raw == nil {
		return additionalCreators, &dump.PowerLevelsConfig{
			Users:         users,
			EventsDefault: 0,
			StateDefault:  defaultStatePowerLevel,
			Ban:           defaultActionPowerLevel,
			Kick:          defaultActionPowerLevel,
			Redact:        defaultActionPowerLevel,
			Invite:        0,
		}
	}

	cfg := &dump.PowerLevelsConfig{
		Users:         users,
		Events:        maps.Clone(raw.Events),
		Notifications: maps.Clone(raw.Notifications),
		UsersDefault:  derefOr(raw.UsersDefault, 0),
		EventsDefault: derefOr(raw.EventsDefault, 0),
		StateDefault:  derefOr(raw.StateDefault, defaultStatePowerLevel),
		Ban:           derefOr(raw.Ban, defaultActionPowerLevel),
		Kick:          derefOr(raw.Kick, defaultActionPowerLevel),
		Redact:        derefOr(raw.Redact, defaultActionPowerLevel),
		Invite:        derefOr(raw.Invite, 0),
	}
	return additionalCreators, cfg
}

func pruneEmptyAndBridgeSpaces(corpus *Corpus, partialByRoom map[string]PartialLocalRoom) {
	migratedIDs := buildMigratedRoomSet(corpus)
	initialChildren := snapshotSpaceChildren(corpus.LocalRooms)
	prunedAnySpace := false
	for {
		pruneUnmigratedSpaceChildren(corpus.LocalRooms, migratedIDs)
		removedInPass := false
		keptLocal := make([]dump.LocalRoom, 0, len(corpus.LocalRooms))
		for i := range corpus.LocalRooms {
			room := &corpus.LocalRooms[i]
			if room.RoomType != roomTypeSpace || len(room.SpaceChildren) > 0 {
				keptLocal = append(keptLocal, *room)
				continue
			}
			removedInPass = true
			prunedAnySpace = true
			delete(migratedIDs, room.OldRoomID)
			reason := prunedSpaceReason(room.OldRoomID, initialChildren[room.OldRoomID], corpus.BridgeOrOrphanRooms)
			excludePrunedSpace(corpus, room, reason, partialByRoom)
		}
		corpus.LocalRooms = keptLocal
		if !removedInPass {
			break
		}
	}
	if prunedAnySpace {
		sort.Slice(corpus.ExcludedRooms, func(i, j int) bool {
			return corpus.ExcludedRooms[i].RoomID < corpus.ExcludedRooms[j].RoomID
		})
	}
}

func buildMigratedRoomSet(corpus *Corpus) map[string]struct{} {
	migrated := make(map[string]struct{}, len(corpus.LocalRooms)+len(corpus.FederatedRooms))
	for i := range corpus.LocalRooms {
		migrated[corpus.LocalRooms[i].OldRoomID] = struct{}{}
	}
	for i := range corpus.FederatedRooms {
		migrated[corpus.FederatedRooms[i].RoomID] = struct{}{}
	}
	return migrated
}

func snapshotSpaceChildren(rooms []dump.LocalRoom) map[string][]dump.SpaceChildEntry {
	out := make(map[string][]dump.SpaceChildEntry)
	for i := range rooms {
		if rooms[i].RoomType == roomTypeSpace {
			out[rooms[i].OldRoomID] = slices.Clone(rooms[i].SpaceChildren)
		}
	}
	return out
}

func prunedSpaceReason(roomID string, initialChildren []dump.SpaceChildEntry, excluded map[string]struct{}) string {
	var hasExcluded, hasUnjoined bool
	for _, child := range initialChildren {
		if child.ChildRoomID == roomID {
			continue
		}
		if _, isExcluded := excluded[child.ChildRoomID]; isExcluded {
			hasExcluded = true
		} else {
			hasUnjoined = true
		}
	}
	switch {
	case hasExcluded && hasUnjoined:
		return "all child rooms in this space were excluded from migration or have no joined allowlisted members"
	case hasExcluded:
		return "all child rooms in this space were excluded from migration"
	case hasUnjoined:
		return "all child rooms in this space have no joined allowlisted members"
	default:
		return "space contains no child rooms"
	}
}

func excludePrunedSpace(corpus *Corpus, room *dump.LocalRoom, reason string, partialByRoom map[string]PartialLocalRoom) {
	corpus.BridgeOrOrphanRooms[room.OldRoomID] = struct{}{}
	corpus.BridgeOrphanReasons[room.OldRoomID] = reason
	excluded := ExcludedRoom{
		RoomID:           room.OldRoomID,
		RoomName:         room.Name,
		Reason:           reason,
		JoinedLocalUsers: slices.Clone(room.JoinedMembers),
	}
	if partial, hasPartial := partialByRoom[room.OldRoomID]; hasPartial {
		excluded.ExcludedJoinedLocalUsers = partial.ExcludedJoinedLocalUsers
		excluded.DepartedLocalUsers = partial.DepartedLocalUsers
		excluded.DepartedExternalUsers = partial.DepartedExternalUsers
		delete(partialByRoom, room.OldRoomID)
	}
	corpus.ExcludedRooms = append(corpus.ExcludedRooms, excluded)
}

func collectPartialLocalRooms(corpus *Corpus, partialByRoom map[string]PartialLocalRoom) {
	if len(partialByRoom) == 0 {
		return
	}
	corpus.PartialLocalRooms = make([]PartialLocalRoom, 0, len(partialByRoom))
	for i := range corpus.LocalRooms {
		if partial, ok := partialByRoom[corpus.LocalRooms[i].OldRoomID]; ok {
			corpus.PartialLocalRooms = append(corpus.PartialLocalRooms, partial)
		}
	}
}

func pruneUnmigratedSpaceChildren(rooms []dump.LocalRoom, migratedIDs map[string]struct{}) {
	for i := range rooms {
		if len(rooms[i].SpaceChildren) == 0 {
			continue
		}
		filtered := make([]dump.SpaceChildEntry, 0, len(rooms[i].SpaceChildren))
		for _, child := range rooms[i].SpaceChildren {
			if child.ChildRoomID == rooms[i].OldRoomID {
				continue
			}
			if _, ok := migratedIDs[child.ChildRoomID]; !ok {
				continue
			}
			filtered = append(filtered, child)
		}
		rooms[i].SpaceChildren = filtered
	}
}

// FilterDirectMap removes local non-allowlisted partners and bridge or orphan rooms from m.direct data.
func FilterDirectMap(direct map[string][]string, allowlisted map[string]struct{}, serverName string, excludedRooms map[string]struct{}) map[string][]string {
	cleaned := make(map[string][]string, len(direct))
	for partner, roomIDs := range direct {
		if extractServerName(partner) == serverName {
			if _, ok := allowlisted[partner]; !ok {
				continue
			}
		}
		filtered := make([]string, 0, len(roomIDs))
		seen := make(map[string]struct{}, len(roomIDs))
		for _, roomID := range roomIDs {
			if _, skip := excludedRooms[roomID]; skip {
				continue
			}
			if _, dup := seen[roomID]; dup {
				continue
			}
			seen[roomID] = struct{}{}
			filtered = append(filtered, roomID)
		}
		if len(filtered) > 0 {
			cleaned[partner] = filtered
		}
	}
	return cleaned
}

// RemapDirectMap translates migrated local room IDs to their newly created Tuwunel Room v12 IDs.
func RemapDirectMap(direct map[string][]string, localRoomMap map[string]string) map[string][]string {
	remapped := make(map[string][]string, len(direct))
	for partner, roomIDs := range direct {
		out := make([]string, 0, len(roomIDs))
		seen := make(map[string]struct{}, len(roomIDs))
		for _, roomID := range roomIDs {
			targetID := roomID
			if mapped, ok := localRoomMap[roomID]; ok {
				targetID = mapped
			}
			if _, dup := seen[targetID]; dup {
				continue
			}
			seen[targetID] = struct{}{}
			out = append(out, targetID)
		}
		if len(out) > 0 {
			remapped[partner] = out
		}
	}
	return remapped
}

// FilterRoomKeys removes Megolm backup sessions belonging to excluded bridge or orphan rooms.
func FilterRoomKeys(keys *dump.RoomKeysData, excludedRooms map[string]struct{}) *dump.RoomKeysData {
	if keys == nil {
		return nil
	}
	filteredRooms := make(map[string]dump.RoomKeyBackupRoom, len(keys.Rooms))
	for roomID, entry := range keys.Rooms {
		if _, skip := excludedRooms[roomID]; skip {
			continue
		}
		filteredRooms[roomID] = entry
	}
	return &dump.RoomKeysData{
		UserID: keys.UserID,
		Rooms:  filteredRooms,
	}
}

func memberPowerLevel(userID string, pl *powerLevelsRaw) int {
	if pl == nil {
		return 0
	}
	if level, ok := pl.Users[userID]; ok {
		return level
	}
	if pl.UsersDefault != nil {
		return *pl.UsersDefault
	}
	return 0
}

func extractServerName(userID string) string {
	trimmed := strings.TrimPrefix(userID, "@")
	_, server, ok := strings.Cut(trimmed, ":")
	if !ok {
		return ""
	}
	return server
}

func dedupeSorted(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func derefOr(val *int, fallback int) int {
	if val != nil {
		return *val
	}
	return fallback
}
