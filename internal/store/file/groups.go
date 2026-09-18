package file

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

// Group Repository

type groupRepository struct {
	store *Store
}

type membership struct {
	UserID  string `json:"user_id"`
	GroupID string `json:"group_id"`
}

type groupsData struct {
	Groups      []*domain.Group `json:"groups"`
	Memberships []membership    `json:"memberships"`
}

func (r *groupRepository) load() (*groupsData, error) {
	var data groupsData
	if err := r.store.readFile("groups", &data); err != nil {
		return nil, err
	}
	if data.Groups == nil {
		data.Groups = []*domain.Group{}
	}
	if data.Memberships == nil {
		data.Memberships = []membership{}
	}
	return &data, nil
}

func (r *groupRepository) save(data *groupsData) error {
	return r.store.writeFile("groups", data)
}

func (r *groupRepository) Create(ctx context.Context, group *domain.Group) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load groups", err)
	}
	for _, g := range data.Groups {
		if g.ID == group.ID {
			return idperrors.AlreadyExists("group", group.ID)
		}
		if strings.EqualFold(g.Name, group.Name) {
			return idperrors.AlreadyExists("group with name", group.Name)
		}
	}
	now := time.Now()
	group.CreatedAt = now
	group.UpdatedAt = now
	data.Groups = append(data.Groups, group)
	return r.save(data)
}

func (r *groupRepository) GetByID(ctx context.Context, id string) (*domain.Group, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load groups", err)
	}
	for _, g := range data.Groups {
		if g.ID == id {
			return g, nil
		}
	}
	return nil, idperrors.NotFound("group", id)
}

func (r *groupRepository) GetByName(ctx context.Context, name string) (*domain.Group, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load groups", err)
	}
	for _, g := range data.Groups {
		if strings.EqualFold(g.Name, name) {
			return g, nil
		}
	}
	return nil, idperrors.NotFound("group with name", name)
}

func (r *groupRepository) Update(ctx context.Context, group *domain.Group) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load groups", err)
	}
	for _, g := range data.Groups {
		if g.ID != group.ID && strings.EqualFold(g.Name, group.Name) {
			return idperrors.AlreadyExists("group with name", group.Name)
		}
	}
	for i, g := range data.Groups {
		if g.ID == group.ID {
			group.UpdatedAt = time.Now()
			data.Groups[i] = group
			return r.save(data)
		}
	}
	return idperrors.NotFound("group", group.ID)
}

func (r *groupRepository) Delete(ctx context.Context, id string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load groups", err)
	}
	for i, g := range data.Groups {
		if g.ID == id {
			data.Groups = append(data.Groups[:i], data.Groups[i+1:]...)
			kept := data.Memberships[:0]
			for _, m := range data.Memberships {
				if m.GroupID != id {
					kept = append(kept, m)
				}
			}
			data.Memberships = kept
			return r.save(data)
		}
	}
	return idperrors.NotFound("group", id)
}

func (r *groupRepository) List(ctx context.Context) ([]*domain.Group, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load groups", err)
	}
	sortGroups(data.Groups)
	return data.Groups, nil
}

func (r *groupRepository) AddMember(ctx context.Context, groupID, userID string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load groups", err)
	}
	if _, err := r.findGroup(data, groupID); err != nil {
		return err
	}
	for _, m := range data.Memberships {
		if m.GroupID == groupID && m.UserID == userID {
			return nil
		}
	}
	data.Memberships = append(data.Memberships, membership{UserID: userID, GroupID: groupID})
	return r.save(data)
}

func (r *groupRepository) RemoveMember(ctx context.Context, groupID, userID string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load groups", err)
	}
	for i, m := range data.Memberships {
		if m.GroupID == groupID && m.UserID == userID {
			data.Memberships = append(data.Memberships[:i], data.Memberships[i+1:]...)
			return r.save(data)
		}
	}
	return idperrors.NotFound("group membership", userID+"/"+groupID)
}

func (r *groupRepository) MemberIDs(ctx context.Context, groupID string) ([]string, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load groups", err)
	}
	ids := []string{}
	for _, m := range data.Memberships {
		if m.GroupID == groupID {
			ids = append(ids, m.UserID)
		}
	}
	return ids, nil
}

func (r *groupRepository) GroupsForUser(ctx context.Context, userID string) ([]*domain.Group, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load groups", err)
	}
	byID := make(map[string]*domain.Group, len(data.Groups))
	for _, g := range data.Groups {
		byID[g.ID] = g
	}
	groups := []*domain.Group{}
	for _, m := range data.Memberships {
		if m.UserID == userID {
			if g, ok := byID[m.GroupID]; ok {
				groups = append(groups, g)
			}
		}
	}
	sortGroups(groups)
	return groups, nil
}

func (r *groupRepository) RemoveUser(ctx context.Context, userID string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load groups", err)
	}
	kept := data.Memberships[:0]
	for _, m := range data.Memberships {
		if m.UserID != userID {
			kept = append(kept, m)
		}
	}
	data.Memberships = kept
	return r.save(data)
}

func (r *groupRepository) findGroup(data *groupsData, id string) (*domain.Group, error) {
	for _, g := range data.Groups {
		if g.ID == id {
			return g, nil
		}
	}
	return nil, idperrors.NotFound("group", id)
}

func sortGroups(groups []*domain.Group) {
	sort.Slice(groups, func(i, j int) bool {
		return strings.ToLower(groups[i].Name) < strings.ToLower(groups[j].Name)
	})
}
