package rest

import (
	"log"
	"net/http"

	"github.com/pasarguard/node/common"
)

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	s.LockControl()
	defer s.UnlockControl()

	data := &common.Backend{}

	if err := common.ReadProtoBody(r.Body, data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ip, ok := requestClientIP(r)
	if !ok {
		http.Error(w, "unknown ip", http.StatusServiceUnavailable)
		return
	}

	running := s.Backend() != nil
	if running && !s.IsCurrentClient(ip) {
		http.Error(w, "node is controlled by another client", http.StatusForbidden)
		return
	}

	// An additive Start brings up one more core on a node that is already
	// serving. A plain Start is the panel connecting, which resets the node so
	// that it runs exactly the cores that connection brings and nothing stale.
	additive := running && data.GetAdditive()
	if running && !additive {
		log.Println("New connection from ", ip, " core control access was taken away from previous client.")
		s.Disconnect()
	}

	if err := s.StartBackend(r.Context(), data); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if additive {
		s.NewRequest()
	} else {
		s.Connect(ip, data.GetKeepAlive())
	}

	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	s.LockControl()
	defer s.UnlockControl()

	s.Disconnect()

	common.SendProtoResponse(w, &common.Empty{})
}
