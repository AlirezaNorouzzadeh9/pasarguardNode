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

	if s.Backend() != nil {
		if !s.IsCurrentClient(ip) {
			http.Error(w, "node is controlled by another client", http.StatusForbidden)
			return
		}
		log.Println("New connection from ", ip, " core control access was taken away from previous client.")
		s.Disconnect()
	}

	if err := s.StartBackend(r.Context(), data); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	s.Connect(ip, data.GetKeepAlive())

	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	s.LockControl()
	defer s.UnlockControl()

	s.Disconnect()

	common.SendProtoResponse(w, &common.Empty{})
}
