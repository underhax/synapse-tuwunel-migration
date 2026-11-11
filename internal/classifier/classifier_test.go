package classifier

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/underhax/synapse-tuwunel-migration/internal/dump"
)

func rawState(t *testing.T, evType, stateKey, sender string, payload any) StateEvent {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal state %s: %v", evType, err)
	}
	return StateEvent{
		Type:     evType,
		StateKey: stateKey,
		Sender:   sender,
		Content:  raw,
	}
}

func makeMemberEvent(t *testing.T, userID, membership string) StateEvent {
	return rawState(t, eventTypeMember, userID, userID, memberContent{Membership: membership})
}

func TestClassifyBridgeAndOrphanRooms(t *testing.T) {
	tests := []struct {
		buildExtra         func(server, localUser string) []StateEvent
		name               string
		server             string
		wantReason         string
		wantBridgeUsers    []string
		wantExcludedJoined []string
		wantDepartedLocal  []string
		wantDepartedExt    []string
		noLocal            bool
	}{
		{
			name:       "m.bridge state marker",
			server:     "b1.example.com",
			wantReason: "room is linked to a bridge via m.bridge state event",
			buildExtra: func(server, _ string) []StateEvent {
				return []StateEvent{rawState(t, eventTypeBridge, "bridge-key", "@bridgebot:"+server, map[string]string{"channel": "1"})}
			},
		},
		{
			name:       "uk.half-shot.bridge state marker",
			server:     "b2.example.net",
			wantReason: "room is linked to a bridge via uk.half-shot.bridge state event",
			buildExtra: func(server, _ string) []StateEvent {
				return []StateEvent{rawState(t, eventTypeHalfShotBridge, "hs-key", "@hsbot:"+server, map[string]string{})}
			},
		},
		{
			name:       "fi.mau.bridge marker",
			server:     "b3.example.org",
			wantReason: "room is linked to a bridge via fi.mau.whatsapp.portal state event",
			buildExtra: func(server, _ string) []StateEvent {
				return []StateEvent{rawState(t, "fi.mau.whatsapp.portal", "", "@wabot:"+server, map[string]string{})}
			},
		},
		{
			name:            "io.element.functional_members non-allowlisted bot",
			server:          "b4.example",
			wantReason:      "room contains non-allowlisted functional service members (io.element.functional_members)",
			wantBridgeUsers: []string{"@bot:b4.example"},
			buildExtra: func(server, localUser string) []StateEvent {
				return []StateEvent{rawState(t, eventTypeFuncMembers, "", localUser, functionalMembersContent{
					ServiceMembers: []string{"@bot:" + server},
				})}
			},
		},
		{
			name:            "explicit bridge takes priority over io.element.functional_members",
			server:          "b4b.example.com",
			wantReason:      "room is linked to a bridge via m.bridge state event",
			wantBridgeUsers: []string{"@bot:b4b.example.com"},
			buildExtra: func(server, localUser string) []StateEvent {
				return []StateEvent{
					rawState(t, eventTypeFuncMembers, "", localUser, functionalMembersContent{
						ServiceMembers: []string{"@bot:" + server},
					}),
					rawState(t, eventTypeBridge, "", "@bridgebot:"+server, map[string]string{}),
				}
			},
		},
		{
			name:               "single allowlisted local with active non-allowlisted local",
			server:             "b5a.example.com",
			wantReason:         "only 1 allowlisted local member remains after excluding non-allowlisted local participants",
			wantExcludedJoined: []string{"@support:b5a.example.com"},
			buildExtra: func(server, _ string) []StateEvent {
				return []StateEvent{makeMemberEvent(t, "@support:"+server, membershipJoin)}
			},
		},
		{
			name:              "single allowlisted local with departed non-allowlisted local",
			server:            "b5.example.com",
			wantReason:        "only 1 allowlisted local member remains after excluding non-allowlisted local participants",
			wantDepartedLocal: []string{"@telegram_42:b5.example.com"},
			buildExtra: func(server, _ string) []StateEvent {
				return []StateEvent{makeMemberEvent(t, "@telegram_42:"+server, "leave")}
			},
		},
		{
			name:            "single allowlisted local with departed external federated member",
			server:          "b6.example.net",
			wantReason:      "only 1 allowlisted local member remains because all external federated members have departed",
			wantDepartedExt: []string{"@ext:fed1.example.org"},
			buildExtra: func(_, _ string) []StateEvent {
				return []StateEvent{makeMemberEvent(t, "@ext:fed1.example.org", "leave")}
			},
		},
		{
			name:               "single allowlisted local with non-allowlisted local and departed external",
			server:             "b6b.example.net",
			wantReason:         "only 1 allowlisted local member remains after excluding non-allowlisted local and departed external participants",
			wantExcludedJoined: []string{"@support:b6b.example.net"},
			wantDepartedExt:    []string{"@ext:fed2.example.net"},
			buildExtra: func(server, _ string) []StateEvent {
				return []StateEvent{
					makeMemberEvent(t, "@support:"+server, membershipJoin),
					makeMemberEvent(t, "@ext:fed2.example.net", "leave"),
				}
			},
		},
		{
			name:       "single allowlisted local after allowlisted peer departed",
			server:     "b6c.example.org",
			wantReason: "only 1 allowlisted local member remains because all other allowlisted local members have departed",
			buildExtra: func(server, _ string) []StateEvent {
				return []StateEvent{makeMemberEvent(t, "@bob:"+server, "leave")}
			},
		},
		{
			name:       "no joined local user",
			server:     "b7.example.org",
			wantReason: "no allowlisted local member is currently joined",
			noLocal:    true,
		},
		{
			name:       "empty space with no child rooms",
			server:     "b9.example",
			wantReason: "space contains no child rooms",
			buildExtra: func(_, localUser string) []StateEvent {
				return []StateEvent{rawState(t, eventTypeCreate, "", localUser, createContent{Type: roomTypeSpace})}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			localUser := "@alice:" + tc.server
			allowlisted := map[string]struct{}{localUser: {}, "@bob:" + tc.server: {}}
			opts := ClassifyOptions{
				ServerName:       tc.server,
				LocalRoomVersion: "12",
				AllowlistedUsers: allowlisted,
			}
			events := []StateEvent{
				makeMemberEvent(t, localUser, membershipJoin),
				rawState(t, eventTypeName, "", localUser, textContent{Name: "Excluded Test Room"}),
			}
			if tc.buildExtra != nil {
				events = append(events, tc.buildExtra(tc.server, localUser)...)
			}
			var joined []string
			if !tc.noLocal {
				joined = []string{localUser}
			}
			obs := RoomObservation{
				RoomID:           "!room:" + tc.server,
				JoinedLocalUsers: joined,
				StateEvents:      events,
			}
			assertExcludedOutcome(t, &obs, opts, tc.wantReason, tc.wantBridgeUsers, tc.wantExcludedJoined, tc.wantDepartedLocal, tc.wantDepartedExt)
		})
	}
}

func assertExcludedOutcome(
	t *testing.T,
	obs *RoomObservation,
	opts ClassifyOptions,
	wantReason string,
	wantBridgeUsers []string,
	wantExcludedJoined []string,
	wantDepartedLocal []string,
	wantDepartedExt []string,
) {
	t.Helper()
	res := ClassifyRoom(obs, opts)
	if res.Category != CategoryBridgeOrOrphan {
		t.Errorf("got category %q, want %q", res.Category, CategoryBridgeOrOrphan)
	}
	if res.SkipReason != wantReason {
		t.Errorf("SkipReason = %q, want %q", res.SkipReason, wantReason)
	}
	if res.RoomName != "Excluded Test Room" {
		t.Errorf("got RoomName %q, want %q", res.RoomName, "Excluded Test Room")
	}
	if !slices.Equal(res.BridgeUsers, wantBridgeUsers) {
		t.Errorf("BridgeUsers = %v, want %v", res.BridgeUsers, wantBridgeUsers)
	}
	if !slices.Equal(res.ExcludedJoinedLocalUsers, wantExcludedJoined) {
		t.Errorf("ExcludedJoinedLocalUsers = %v, want %v", res.ExcludedJoinedLocalUsers, wantExcludedJoined)
	}
	if !slices.Equal(res.DepartedLocalUsers, wantDepartedLocal) {
		t.Errorf("DepartedLocalUsers = %v, want %v", res.DepartedLocalUsers, wantDepartedLocal)
	}
	if !slices.Equal(res.DepartedExternalUsers, wantDepartedExt) {
		t.Errorf("DepartedExternalUsers = %v, want %v", res.DepartedExternalUsers, wantDepartedExt)
	}
}

func TestClassifyBridgeMalformedAndFallback(t *testing.T) {
	malformedCases := []struct {
		roomID string
		server string
		userID string
	}{
		{
			roomID: "!malformed:b8.example.com",
			server: "b8.example.com",
			userID: "@alice:b8.example.com",
		},
	}
	for _, mc := range malformedCases {
		obs := RoomObservation{
			RoomID:           mc.roomID,
			JoinedLocalUsers: []string{mc.userID},
			StateEvents: []StateEvent{
				makeMemberEvent(t, mc.userID, membershipJoin),
				{
					Type:    eventTypeFuncMembers,
					Sender:  mc.userID,
					Content: json.RawMessage(`{invalid`),
				},
			},
		}
		malRes := ClassifyRoom(&obs, ClassifyOptions{
			ServerName:       mc.server,
			AllowlistedUsers: map[string]struct{}{mc.userID: {}},
		})
		if malRes.Category != CategorySingleUserNote {
			t.Errorf("malformed functional_members category = %q, want %q", malRes.Category, CategorySingleUserNote)
		}
	}

	noMemberStateObs := RoomObservation{
		RoomID:           "!nomember:b10.example.com",
		JoinedLocalUsers: []string{"@alice:b10.example.com"},
	}
	noMemberRes := ClassifyRoom(&noMemberStateObs, ClassifyOptions{
		ServerName:       "b10.example.com",
		AllowlistedUsers: map[string]struct{}{"@alice:b10.example.com": {}},
	})
	if noMemberRes.Category != CategoryLocalRoom || noMemberRes.Local == nil || noMemberRes.Local.Category != dump.RoomCategoryLocal {
		t.Errorf("single joined local without member state = %+v", noMemberRes)
	}
}

func TestClassifyFederatedRoomViaRanking(t *testing.T) {
	uAlice := "@alice:fed.example.com"
	uBob := "@bob:fed.example.com"
	opts := ClassifyOptions{
		ServerName:       "fed.example.com",
		LocalRoomVersion: "12",
		AllowlistedUsers: map[string]struct{}{uAlice: {}, uBob: {}},
	}
	obs := RoomObservation{
		RoomID:           "!fed:partner.example.org",
		JoinedLocalUsers: []string{uBob, uAlice, uAlice},
		StateEvents: []StateEvent{
			makeMemberEvent(t, uAlice, membershipJoin),
			makeMemberEvent(t, "@u1:low.example.net", membershipJoin),
			makeMemberEvent(t, "@u4:many.example.org", membershipJoin),
			makeMemberEvent(t, "@u5:many.example.org", membershipJoin),
			makeMemberEvent(t, "@u2:count.example.net", membershipJoin),
			makeMemberEvent(t, "@u3:count.example.net", membershipJoin),
			makeMemberEvent(t, "@admin:top.example.org", membershipJoin),
			makeMemberEvent(t, "@tie1:b-tie.example.org", membershipJoin),
			makeMemberEvent(t, "@tie2:a-tie.example.org", membershipJoin),
			makeMemberEvent(t, "@left:gone.example.org", "leave"),
			makeMemberEvent(t, "malformed-user", membershipJoin),
			rawState(t, eventTypePowerLevels, "", "@admin:top.example.org", map[string]any{
				"users": map[string]int{
					"@admin:top.example.org":  100,
					"@tie1:b-tie.example.org": 50,
					"@tie2:a-tie.example.org": 50,
					"@u2:count.example.net":   25,
					"@u3:count.example.net":   60,
					uAlice:                    0,
				},
				"users_default": 10,
			}),
		},
	}

	res := ClassifyRoom(&obs, opts)
	if res.Category != CategoryFederated {
		t.Fatalf("Category = %q, want %q", res.Category, CategoryFederated)
	}
	wantVia := []string{"top.example.org", "count.example.net", "a-tie.example.org", "b-tie.example.org", "many.example.org", "low.example.net"}
	if !slices.Equal(res.Federated.ViaServers, wantVia) {
		t.Errorf("ViaServers = %v, want %v", res.Federated.ViaServers, wantVia)
	}
	if !slices.Equal(res.Federated.JoinedLocalUsers, []string{uAlice, uBob}) {
		t.Errorf("JoinedLocalUsers = %v", res.Federated.JoinedLocalUsers)
	}
}

func TestClassifySingleUserNotes(t *testing.T) {
	owner := "@notes-owner:notes.example.net"
	opts := ClassifyOptions{
		ServerName:       "notes.example.net",
		LocalRoomVersion: "12",
		AllowlistedUsers: map[string]struct{}{owner: {}},
	}
	maxLife := int64(3600000)

	notesObs := RoomObservation{
		RoomID:           "!notes:notes.example.net",
		JoinedLocalUsers: []string{owner},
		StateEvents: []StateEvent{
			rawState(t, eventTypeCreate, "", "", createContent{Creator: owner}),
			rawState(t, eventTypeFuncMembers, "", owner, functionalMembersContent{ServiceMembers: []string{owner}}),
			makeMemberEvent(t, owner, membershipJoin),
			rawState(t, eventTypeName, "", owner, textContent{Name: "Saved Notes"}),
			rawState(t, eventTypeTopic, "", owner, textContent{Topic: "Private"}),
			rawState(t, eventTypeRetention, "", owner, retentionRaw{MaxLifetime: &maxLife}),
			rawState(t, eventTypeEncryption, "", owner, encryptionRaw{Algorithm: "m.megolm.v1.aes-sha2", RotationPeriodMillis: 604800000, RotationPeriodMsgs: 100}),
		},
	}
	notesRes := ClassifyRoom(&notesObs, opts)
	if notesRes.Category != CategorySingleUserNote || notesRes.Local.Category != dump.RoomCategoryNotes {
		t.Fatalf("Notes category = %q / %q", notesRes.Category, notesRes.Local.Category)
	}
	if notesRes.Local.OriginalCreator != owner || notesRes.Local.Retention == nil || *notesRes.Local.Retention.MaxLifetime != maxLife {
		t.Errorf("Unexpected notes metadata: %+v", notesRes.Local)
	}
}

func TestClassifyLocalDMAndCreatorSelection(t *testing.T) {
	dmOwner := "@carol:dm.example.org"
	dmMod := "@alice:dm.example.org"
	dmAdmin := "@bob:dm.example.org"
	opts := ClassifyOptions{
		ServerName:       "dm.example.org",
		LocalRoomVersion: "12",
		AllowlistedUsers: map[string]struct{}{dmOwner: {}, dmMod: {}, dmAdmin: {}},
		DirectRoomIDs:    map[string]struct{}{"!dm:dm.example.org": {}},
	}

	dmObs := RoomObservation{
		RoomID:           "!dm:dm.example.org",
		JoinedLocalUsers: []string{dmMod, dmAdmin},
		AvatarMXC:        "mxc://dm.example.org/roomav",
		AvatarSHA256:     "abcd",
		AvatarType:       "image/png",
		AvatarSize:       42,
		StateEvents: []StateEvent{
			rawState(t, eventTypeCreate, "", dmOwner, createContent{}),
			makeMemberEvent(t, dmOwner, "leave"),
			makeMemberEvent(t, dmMod, membershipJoin),
			makeMemberEvent(t, dmAdmin, membershipJoin),
			rawState(t, eventTypeHistoryVis, "", dmOwner, textContent{HistoryVisibility: "shared"}),
			rawState(t, eventTypeJoinRules, "", dmOwner, textContent{JoinRule: "invite"}),
			rawState(t, eventTypeGuestAccess, "", dmOwner, textContent{GuestAccess: "forbidden"}),
			rawState(t, eventTypePowerLevels, "", dmOwner, map[string]any{
				"users":          map[string]int{dmOwner: 100, dmMod: 50, dmAdmin: 100},
				"users_default":  0,
				"events_default": 10,
				"state_default":  50,
				"ban":            50,
				"kick":           50,
				"redact":         50,
				"invite":         25,
				"events":         map[string]int{"m.room.name": 50},
				"notifications":  map[string]int{"room": 50},
			}),
		},
	}

	dmRes := ClassifyRoom(&dmObs, opts)
	if dmRes.Category != CategoryLocalRoom || !dmRes.Local.IsDirect {
		t.Fatalf("DM category = %q, IsDirect = %v", dmRes.Category, dmRes.Local.IsDirect)
	}
	if dmRes.Local.ChosenCreator != dmAdmin {
		t.Errorf("ChosenCreator = %q, want highest joined PL %s", dmRes.Local.ChosenCreator, dmAdmin)
	}
	if dmRes.Local.Avatar == nil || dmRes.Local.Avatar.SHA256 != "abcd" {
		t.Errorf("Avatar = %+v", dmRes.Local.Avatar)
	}
	if dmRes.Local.PowerLevels.Users[dmMod] != 50 {
		t.Errorf("Moderator power level missing: %+v", dmRes.Local.PowerLevels.Users)
	}
	if _, exists := dmRes.Local.PowerLevels.Users[dmAdmin]; exists {
		t.Errorf("ChosenCreator must be stripped from v12 power_levels.users")
	}
	if _, exists := dmRes.Local.PowerLevels.Users[dmOwner]; exists {
		t.Errorf("Departed user must be stripped from power_levels.users")
	}
}

func TestTransformPowerLevelsAdditionalCreatorsAndV11Fallback(t *testing.T) {
	u1 := "@alice:pl.example.com"
	u2 := "@bob:pl.example.com"
	u3 := "@carol:pl.example.com"
	joined := []string{u1, u2, u3}
	raw := &powerLevelsRaw{
		Users: map[string]int{u1: 100, u2: 100, u3: 50},
	}

	addV12, plV12 := TransformPowerLevels(raw, u1, joined, "12")
	if !slices.Equal(addV12, []string{u2}) {
		t.Errorf("v12 additional_creators = %v, want [%s]", addV12, u2)
	}
	if len(plV12.Users) != 1 || plV12.Users[u3] != 50 {
		t.Errorf("v12 users = %v", plV12.Users)
	}

	addV11, plV11 := TransformPowerLevels(nil, u1, joined, "11")
	if len(addV11) != 0 || plV11.Users[u1] != 100 {
		t.Errorf("v11 fallback = add:%v users:%v", addV11, plV11.Users)
	}
}

func TestClassifyCorpusDeduplicationAndSpacePruning(t *testing.T) {
	uAlice := "@alice:corpus.example"
	uBob := "@bob:corpus.example"
	groupID := "!group:corpus.example"
	bridgeID := "!bridge:corpus.example"
	opts := ClassifyOptions{
		ServerName:       "corpus.example",
		LocalRoomVersion: "",
		AllowlistedUsers: map[string]struct{}{uAlice: {}, uBob: {}},
	}

	observations := []RoomObservation{
		{
			RoomID:           groupID,
			JoinedLocalUsers: []string{uBob},
		},
		{
			RoomID:           groupID,
			JoinedLocalUsers: []string{uAlice},
			AvatarMXC:        "mxc://corpus.example/grp",
			AvatarSHA256:     "1234",
			AvatarType:       "image/jpeg",
			AvatarSize:       10,
			StateEvents: []StateEvent{
				rawState(t, eventTypeCreate, "", uAlice, createContent{}),
				makeMemberEvent(t, uAlice, membershipJoin),
				makeMemberEvent(t, uBob, membershipJoin),
			},
		},
		{
			RoomID:           bridgeID,
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				rawState(t, eventTypeName, "", uAlice, textContent{Name: "Telegram Bridge"}),
				rawState(t, eventTypeFuncMembers, "", uAlice, functionalMembersContent{ServiceMembers: []string{"@tgbot:corpus.example"}}),
				rawState(t, eventTypeBridge, "", "@bridgebot:corpus.example", map[string]string{}),
			},
		},
		{
			RoomID:           "!space:corpus.example",
			JoinedLocalUsers: []string{uAlice, uBob},
			StateEvents: []StateEvent{
				rawState(t, eventTypeCreate, "", uAlice, createContent{Type: "m.space"}),
				makeMemberEvent(t, uAlice, membershipJoin),
				makeMemberEvent(t, uBob, membershipJoin),
				rawState(t, eventTypeSpaceChild, "", uAlice, spaceChildRaw{Via: []string{"alpha.example.com"}}),
				rawState(t, eventTypeSpaceChild, groupID, uAlice, spaceChildRaw{Via: []string{"beta.example.net"}, Order: "1"}),
				rawState(t, eventTypeSpaceChild, bridgeID, uAlice, spaceChildRaw{Via: []string{"gamma.example.org"}}),
				rawState(t, eventTypeSpaceChild, "!removed:corpus.example", uAlice, map[string]string{}),
			},
		},
		{
			RoomID:           "!fedroom:partner.example.org",
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				makeMemberEvent(t, "@ext:partner.example.org", membershipJoin),
				makeMemberEvent(t, uAlice, membershipJoin),
			},
		},
	}

	corpus := ClassifyCorpus(observations, opts)
	if len(corpus.BridgeOrOrphanRooms) != 1 || len(corpus.ExcludedRooms) != 1 || len(corpus.FederatedRooms) != 1 || len(corpus.LocalRooms) != 2 {
		t.Fatalf("unexpected corpus counts: bridge=%d excluded=%d fed=%d local=%d", len(corpus.BridgeOrOrphanRooms), len(corpus.ExcludedRooms), len(corpus.FederatedRooms), len(corpus.LocalRooms))
	}
	ex := corpus.ExcludedRooms[0]
	if ex.RoomID != bridgeID || ex.RoomName != "Telegram Bridge" || !slices.Equal(ex.BridgeUsers, []string{"@tgbot:corpus.example"}) || !slices.Equal(ex.JoinedLocalUsers, []string{uAlice}) {
		t.Errorf("unexpected excluded room metadata: %+v", ex)
	}
	if len(corpus.LocalRooms[0].JoinedMembers) != 2 {
		t.Errorf("dedup failed on %s: joined=%v", groupID, corpus.LocalRooms[0].JoinedMembers)
	}
	space := corpus.LocalRooms[1]
	if len(space.SpaceChildren) != 1 || space.SpaceChildren[0].ChildRoomID != groupID {
		t.Errorf("space pruning failed: %+v", space)
	}
}

func TestSpaceChildrenSortingAndCleanupHelpers(t *testing.T) {
	uAlice := "@alice:space-sort.example.net"
	uBob := "@bob:space-sort.example.net"
	opts := ClassifyOptions{
		ServerName:       "space-sort.example.net",
		LocalRoomVersion: "12",
		AllowlistedUsers: map[string]struct{}{uAlice: {}, uBob: {}},
	}
	spaceObs := RoomObservation{
		RoomID:           "!s2:space-sort.example.net",
		JoinedLocalUsers: []string{uAlice, uBob},
		StateEvents: []StateEvent{
			rawState(t, eventTypeCreate, "", uAlice, createContent{Type: "m.space"}),
			makeMemberEvent(t, uAlice, membershipJoin),
			makeMemberEvent(t, uBob, membershipJoin),
			rawState(t, eventTypeSpaceChild, "!zchild:space-sort.example.net", uAlice, spaceChildRaw{Via: []string{"delta.example"}}),
			rawState(t, eventTypeSpaceChild, "!achild:space-sort.example.net", uAlice, spaceChildRaw{Via: []string{"epsilon.example"}}),
		},
	}
	res := ClassifyRoom(&spaceObs, opts)
	if res.Local.SpaceChildren[0].ChildRoomID != "!achild:space-sort.example.net" {
		t.Errorf("expected sorted children, got %+v", res.Local.SpaceChildren)
	}

	bridgeRoom := "!b1:direct.example.com"
	dmRoom1 := "!dm1:direct.example.com"
	dmRoom2 := "!dm2:direct.example.com"
	newHash := "!v12targethash"

	direct := map[string][]string{
		"@bot:space-sort.example.net":   {bridgeRoom},
		uBob:                            {bridgeRoom, dmRoom1, dmRoom1},
		"@ext:partner.example.org":      {"!fed1:partner.example.org"},
		"@carol:space-sort.example.net": {},
	}
	excluded := map[string]struct{}{bridgeRoom: {}}
	filteredDirect := FilterDirectMap(direct, opts.AllowlistedUsers, "space-sort.example.net", excluded)
	if len(filteredDirect) != 2 || !slices.Equal(filteredDirect[uBob], []string{dmRoom1}) {
		t.Errorf("FilterDirectMap = %+v", filteredDirect)
	}

	remapped := RemapDirectMap(map[string][]string{
		uBob:                            {dmRoom1, dmRoom2},
		"@carol:space-sort.example.net": {},
	}, map[string]string{
		dmRoom1: newHash,
		dmRoom2: newHash,
	})
	if len(remapped) != 1 || !slices.Equal(remapped[uBob], []string{newHash}) {
		t.Errorf("RemapDirectMap = %+v", remapped)
	}

	if FilterRoomKeys(nil, excluded) != nil {
		t.Errorf("FilterRoomKeys(nil) expected nil")
	}
	keys := &dump.RoomKeysData{
		UserID: uAlice,
		Rooms: map[string]dump.RoomKeyBackupRoom{
			bridgeRoom: {},
			dmRoom1:    {},
		},
	}
	filteredKeys := FilterRoomKeys(keys, excluded)
	if len(filteredKeys.Rooms) != 1 {
		t.Errorf("FilterRoomKeys = %+v", filteredKeys.Rooms)
	}
	if memberPowerLevel(uAlice, nil) != 0 {
		t.Errorf("expected 0 power level for nil map")
	}
	if memberPowerLevel(uAlice, &powerLevelsRaw{}) != 0 {
		t.Errorf("expected 0 power level when UsersDefault is nil")
	}
	if len(dedupeSorted([]string{"", "x", "x"})) != 1 {
		t.Errorf("dedupeSorted failed")
	}
	if len(rankViaServers([]string{"invalid"}, nil)) != 0 {
		t.Errorf("expected empty via servers for malformed MXID")
	}
}

func TestClassifyPartialLocalRoomsAndSpaces(t *testing.T) {
	server := "partial.example.com"
	uAlice := "@alice:" + server
	uBob := "@bob:" + server
	uActiveOther := "@teacher:" + server
	uLeftLocal := "@oldbot:" + server
	uLeftExt := "@ext:gone.example.org"
	uActiveExt := "@partner:fed.example.net"

	partialGroupID := "!group:" + server
	bridgedGroupID := "!bridgegroup:" + server
	workSpaceID := "!work:" + server
	waPortalID := "!waportal:" + server
	waSpaceID := "!waspace:" + server
	rootSpaceID := "!rootspace:" + server
	fedRoomID := "!fed:fed.example.net"

	opts := ClassifyOptions{
		ServerName:       server,
		LocalRoomVersion: "12",
		AllowlistedUsers: map[string]struct{}{uAlice: {}, uBob: {}},
	}

	observations := []RoomObservation{
		{
			RoomID:           partialGroupID,
			JoinedLocalUsers: []string{uAlice, uBob},
			StateEvents: []StateEvent{
				rawState(t, eventTypeName, "", uAlice, textContent{Name: "Shared Group"}),
				makeMemberEvent(t, uAlice, membershipJoin),
				makeMemberEvent(t, uBob, membershipJoin),
				makeMemberEvent(t, uActiveOther, membershipJoin),
				makeMemberEvent(t, uLeftLocal, "leave"),
				makeMemberEvent(t, uLeftExt, "leave"),
			},
		},
		{
			RoomID:           bridgedGroupID,
			JoinedLocalUsers: []string{uAlice, uBob},
			StateEvents: []StateEvent{
				rawState(t, eventTypeName, "", uAlice, textContent{Name: "Relay Bridge"}),
				rawState(t, eventTypeBridge, "", uAlice, map[string]string{}),
				makeMemberEvent(t, uAlice, membershipJoin),
				makeMemberEvent(t, uBob, membershipJoin),
			},
		},
		{
			RoomID:           fedRoomID,
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				makeMemberEvent(t, uAlice, membershipJoin),
				makeMemberEvent(t, uActiveExt, membershipJoin),
			},
		},
		{
			RoomID:           workSpaceID,
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				rawState(t, eventTypeCreate, "", uAlice, createContent{Type: roomTypeSpace}),
				rawState(t, eventTypeName, "", uAlice, textContent{Name: "Work"}),
				makeMemberEvent(t, uAlice, membershipJoin),
				makeMemberEvent(t, uLeftExt, "leave"),
				rawState(t, eventTypeSpaceChild, fedRoomID, uAlice, spaceChildRaw{Via: []string{"fed.example.net"}}),
				rawState(t, eventTypeSpaceChild, partialGroupID, uAlice, spaceChildRaw{Via: []string{server}}),
				rawState(t, eventTypeSpaceChild, waPortalID, uAlice, spaceChildRaw{Via: []string{server}}),
				rawState(t, eventTypeSpaceChild, "!stale-work:"+server, uAlice, spaceChildRaw{Via: []string{server}}),
			},
		},
		{
			RoomID:           waPortalID,
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				rawState(t, "fi.mau.whatsapp.portal", "", "@wabot:"+server, map[string]string{}),
				makeMemberEvent(t, uAlice, membershipJoin),
			},
		},
		{
			RoomID:           waSpaceID,
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				rawState(t, eventTypeCreate, "", uAlice, createContent{Type: roomTypeSpace}),
				rawState(t, eventTypeName, "", uAlice, textContent{Name: "WhatsApp"}),
				makeMemberEvent(t, uAlice, membershipJoin),
				makeMemberEvent(t, uActiveOther, membershipJoin),
				rawState(t, eventTypeSpaceChild, waPortalID, uAlice, spaceChildRaw{Via: []string{server}}),
			},
		},
		{
			RoomID:           rootSpaceID,
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				rawState(t, eventTypeCreate, "", uAlice, createContent{Type: roomTypeSpace}),
				rawState(t, eventTypeName, "", uAlice, textContent{Name: "All Bridges"}),
				makeMemberEvent(t, uAlice, membershipJoin),
				rawState(t, eventTypeSpaceChild, waSpaceID, uAlice, spaceChildRaw{Via: []string{server}}),
			},
		},
	}

	corpus := ClassifyCorpus(observations, opts)
	assertPartialCorpusOutcomes(t, &corpus, uAlice, uBob, uActiveOther, uLeftLocal, uLeftExt, partialGroupID, bridgedGroupID, workSpaceID, waSpaceID, rootSpaceID, fedRoomID)
}

func assertPartialCorpusOutcomes(
	t *testing.T,
	corpus *Corpus,
	uAlice, uBob, uActiveOther, uLeftLocal, uLeftExt string,
	partialGroupID, bridgedGroupID, workSpaceID, waSpaceID, rootSpaceID, fedRoomID string,
) {
	t.Helper()
	if len(corpus.LocalRooms) != 2 {
		t.Fatalf("LocalRooms len = %d, want 2: %+v", len(corpus.LocalRooms), corpus.LocalRooms)
	}
	if len(corpus.FederatedRooms) != 1 || corpus.FederatedRooms[0].RoomID != fedRoomID {
		t.Fatalf("FederatedRooms = %+v", corpus.FederatedRooms)
	}
	if len(corpus.ExcludedRooms) != 4 {
		t.Fatalf("ExcludedRooms len = %d, want 4: %+v", len(corpus.ExcludedRooms), corpus.ExcludedRooms)
	}
	for _, id := range []string{waSpaceID, rootSpaceID, bridgedGroupID} {
		if corpus.BridgeOrphanReasons[id] == "" {
			t.Errorf("missing BridgeOrphanReason for %s: %+v", id, corpus.BridgeOrphanReasons)
		}
	}

	foundWorkSpace := findLocalRoomByID(corpus.LocalRooms, workSpaceID)
	if foundWorkSpace == nil {
		t.Fatalf("expected surviving Work space in LocalRooms")
	}
	if foundWorkSpace.Category != dump.RoomCategoryLocal || foundWorkSpace.RoomType != roomTypeSpace {
		t.Errorf("Work space category/type = %q / %q", foundWorkSpace.Category, foundWorkSpace.RoomType)
	}
	if len(foundWorkSpace.SpaceChildren) != 2 || foundWorkSpace.SpaceChildren[0].ChildRoomID != fedRoomID || foundWorkSpace.SpaceChildren[1].ChildRoomID != partialGroupID {
		t.Errorf("Work SpaceChildren = %+v", foundWorkSpace.SpaceChildren)
	}

	assertPartialLocalWarnings(t, corpus, uAlice, uBob, uActiveOther, uLeftLocal, uLeftExt, partialGroupID, waSpaceID)
}

func assertPartialLocalWarnings(
	t *testing.T,
	corpus *Corpus,
	uAlice, uBob, uActiveOther, uLeftLocal, uLeftExt string,
	partialGroupID, waSpaceID string,
) {
	t.Helper()
	if len(corpus.PartialLocalRooms) != 2 {
		t.Fatalf("PartialLocalRooms len = %d, want 2: %+v", len(corpus.PartialLocalRooms), corpus.PartialLocalRooms)
	}
	partialGroup := corpus.PartialLocalRooms[0]
	if partialGroup.RoomID != partialGroupID {
		t.Errorf("partialGroup.RoomID = %q, want %q", partialGroup.RoomID, partialGroupID)
	}
	if !slices.Equal(partialGroup.JoinedLocalUsers, []string{uAlice, uBob}) {
		t.Errorf("partialGroup.JoinedLocalUsers = %v", partialGroup.JoinedLocalUsers)
	}
	if !slices.Equal(partialGroup.ExcludedJoinedLocalUsers, []string{uActiveOther}) {
		t.Errorf("partialGroup.ExcludedJoinedLocalUsers = %v", partialGroup.ExcludedJoinedLocalUsers)
	}
	if !slices.Equal(partialGroup.DepartedLocalUsers, []string{uLeftLocal}) {
		t.Errorf("partialGroup.DepartedLocalUsers = %v", partialGroup.DepartedLocalUsers)
	}
	if !slices.Equal(partialGroup.DepartedExternalUsers, []string{uLeftExt}) {
		t.Errorf("partialGroup.DepartedExternalUsers = %v", partialGroup.DepartedExternalUsers)
	}

	foundWaSpaceEx := findExcludedRoomByID(corpus.ExcludedRooms, waSpaceID)
	if foundWaSpaceEx == nil || !slices.Equal(foundWaSpaceEx.ExcludedJoinedLocalUsers, []string{uActiveOther}) {
		t.Errorf("pruned WaSpace excluded metadata = %+v", foundWaSpaceEx)
	}
}

func findLocalRoomByID(rooms []dump.LocalRoom, roomID string) *dump.LocalRoom {
	for i := range rooms {
		if rooms[i].OldRoomID == roomID {
			return &rooms[i]
		}
	}
	return nil
}

func findExcludedRoomByID(rooms []ExcludedRoom, roomID string) *ExcludedRoom {
	for i := range rooms {
		if rooms[i].RoomID == roomID {
			return &rooms[i]
		}
	}
	return nil
}

func TestPruneSpaceWhitelistReasons(t *testing.T) {
	srv := "spaces-prune.example.org"
	uAlice := "@alice:" + srv
	uSignalBot := "@signalbot:" + srv
	opts := ClassifyOptions{
		ServerName:       srv,
		LocalRoomVersion: "12",
		AllowlistedUsers: map[string]struct{}{uAlice: {}},
	}

	localRoomID := "!local:" + srv
	fedRoomID := "!fed:fed.spaces.example.net"
	bridgeRoomID := "!bridge:" + srv
	staleOnlySpaceID := "!stale-space:" + srv
	cascadeParentID := "!cascade-parent:" + srv
	mixedSpaceID := "!mixed-space:" + srv
	excludedOnlySpaceID := "!excluded-only:" + srv
	selfSpaceID := "!self-space:" + srv
	emptySpaceID := "!empty-space:" + srv
	survivingSpaceID := "!surviving-space:" + srv

	observations := []RoomObservation{
		{
			RoomID:           localRoomID,
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				makeMemberEvent(t, uAlice, membershipJoin),
			},
		},
		{
			RoomID:           fedRoomID,
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				makeMemberEvent(t, uAlice, membershipJoin),
				makeMemberEvent(t, "@peer:fed.spaces.example.net", membershipJoin),
			},
		},
		{
			RoomID:           bridgeRoomID,
			JoinedLocalUsers: []string{uAlice},
			StateEvents: []StateEvent{
				rawState(t, "fi.mau.signal.portal", "", uSignalBot, map[string]string{}),
				makeMemberEvent(t, uAlice, membershipJoin),
			},
		},
		makeSpaceObs(t, staleOnlySpaceID, "Signal", uSignalBot, uAlice, []string{"!unjoined-portal:" + srv}, []string{uSignalBot}),
		makeSpaceObs(t, cascadeParentID, "Nested Stale", uAlice, uAlice, []string{staleOnlySpaceID}, nil),
		makeSpaceObs(t, mixedSpaceID, "Mixed Bridge", uAlice, uAlice, []string{bridgeRoomID, "!other-stale:" + srv}, nil),
		makeSpaceObs(t, excludedOnlySpaceID, "Excluded Only", uAlice, uAlice, []string{bridgeRoomID}, nil),
		makeSpaceObs(t, selfSpaceID, "Self Loop", uAlice, uAlice, []string{selfSpaceID}, nil),
		makeSpaceObs(t, emptySpaceID, "Initially Empty", uAlice, uAlice, nil, nil),
		makeSpaceObs(t, survivingSpaceID, "Active Space", uAlice, uAlice, []string{localRoomID, fedRoomID, "!gone-room:" + srv, bridgeRoomID, survivingSpaceID}, nil),
	}

	corpus := ClassifyCorpus(observations, opts)
	if len(corpus.LocalRooms) != 2 {
		t.Fatalf("LocalRooms len = %d, want 2: %+v", len(corpus.LocalRooms), corpus.LocalRooms)
	}
	surviving := findLocalRoomByID(corpus.LocalRooms, survivingSpaceID)
	if surviving == nil || len(surviving.SpaceChildren) != 2 || surviving.SpaceChildren[0].ChildRoomID != fedRoomID || surviving.SpaceChildren[1].ChildRoomID != localRoomID {
		t.Fatalf("unexpected surviving space: %+v", surviving)
	}
	if len(corpus.PartialLocalRooms) != 0 {
		t.Errorf("expected no PartialLocalRooms when bot-created space is pruned, got %+v", corpus.PartialLocalRooms)
	}

	assertExcludedSpaceReasons(t, corpus.ExcludedRooms, []excludedSpaceCase{
		{
			wantReason: "all child rooms in this space have no joined allowlisted members",
			roomIDs:    []string{staleOnlySpaceID},
		},
		{
			wantReason: "all child rooms in this space were excluded from migration",
			roomIDs:    []string{cascadeParentID, excludedOnlySpaceID},
		},
		{
			wantReason: "all child rooms in this space were excluded from migration or have no joined allowlisted members",
			roomIDs:    []string{mixedSpaceID},
		},
		{
			wantReason: "space contains no child rooms",
			roomIDs:    []string{selfSpaceID, emptySpaceID},
		},
	})
}

type excludedSpaceCase struct {
	wantReason string
	roomIDs    []string
}

func assertExcludedSpaceReasons(t *testing.T, excluded []ExcludedRoom, cases []excludedSpaceCase) {
	t.Helper()
	for _, tc := range cases {
		for _, roomID := range tc.roomIDs {
			ex := findExcludedRoomByID(excluded, roomID)
			if ex == nil {
				t.Fatalf("expected %s to be excluded", roomID)
			}
			if ex.Reason != tc.wantReason {
				t.Errorf("%s reason = %q, want %q", roomID, ex.Reason, tc.wantReason)
			}
		}
	}
}

func makeSpaceObs(t *testing.T, roomID, name, creator, joinedUser string, children, extraJoined []string) RoomObservation {
	t.Helper()
	events := make([]StateEvent, 0, 3+len(extraJoined)+len(children))
	events = append(events,
		rawState(t, eventTypeCreate, "", creator, createContent{Type: roomTypeSpace}),
		rawState(t, eventTypeName, "", creator, textContent{Name: name}),
		makeMemberEvent(t, joinedUser, membershipJoin),
	)
	for _, extra := range extraJoined {
		events = append(events, makeMemberEvent(t, extra, membershipJoin))
	}
	for _, childID := range children {
		events = append(events, rawState(t, eventTypeSpaceChild, childID, creator, spaceChildRaw{Via: []string{"via.spaces.example.net"}}))
	}
	return RoomObservation{
		RoomID:           roomID,
		JoinedLocalUsers: []string{joinedUser},
		StateEvents:      events,
	}
}
