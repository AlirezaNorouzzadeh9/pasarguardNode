package rpc

import (
	"context"
	"log"

	"github.com/pasarguard/node/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Service) Start(ctx context.Context, data *common.Backend) (*common.BaseInfoResponse, error) {
	s.LockControl()
	defer s.UnlockControl()

	clientIP := clientIPFromContext(ctx)
	if clientIP == "" {
		return nil, status.Errorf(codes.PermissionDenied, "unknown client ip")
	}

	if s.Backend() != nil {
		if !s.IsCurrentClient(clientIP) {
			return nil, status.Errorf(codes.PermissionDenied, "node is controlled by another client")
		}
		log.Println("New connection from ", clientIP, " core control access was taken away from previous client.")
		s.Disconnect()
	}

	if err := s.StartBackend(ctx, data); err != nil {
		return nil, err
	}

	s.Connect(clientIP, data.GetKeepAlive())

	return s.BaseInfoResponse(), nil
}

func (s *Service) Stop(_ context.Context, _ *common.Empty) (*common.Empty, error) {
	s.LockControl()
	defer s.UnlockControl()

	s.Disconnect()
	return nil, nil
}

func (s *Service) GetBaseInfo(_ context.Context, _ *common.Empty) (*common.BaseInfoResponse, error) {
	return s.BaseInfoResponse(), nil
}
