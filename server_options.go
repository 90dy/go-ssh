package ssh

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type SshServerOption =SshHandlerOption
type SshHandlerOption = func(*SshHandler) error

func WithLogger(logger logrus.FieldLogger) SshHandlerOption {
	return func(handler *SshHandler) error {
		if logger != nil {
			handler.FieldLogger = logger
		}
		return nil
	}
}

func WithConn(conn Conn) SshHandlerOption {
	return func(handler *SshHandler) error {
		for n, option := range []SshHandlerOption{
			WithBanner(conn),
			WithAuth(conn),
			WithGlobalRequest(conn),
			WithChannelSession(conn),
			WithChannelDirectTcpip(conn),
			WithChannelForwardedTcpip(conn),
			WithChannelCustom(conn),
			WithChannelX11(conn),
			WithRequestPty(conn),
			WithRequestX11(conn),
			WithRequestEnv(conn),
			WithRequestShell(conn),
			WithRequestExec(conn),
			WithRequestSubsystem(conn),
			WithRequestWindowChange(conn),
			WithRequestSignal(conn),
			WithRequestXonXoff(conn),
			WithRequestBreak(conn),
			WithRequestCustom(conn),
		} {
			err := option(handler)
			if err != nil {
				return fmt.Errorf("auth option %d: %v", n, err)
			}
		}
		return nil
	}
}

func WithBanner(banner Banner) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.Banner = banner
		handler.BannerCallback = func(c ssh.ConnMetadata) string {
			if handler.Banner != nil {
				return handler.Banner.SshBanner(handler.Context, c)
			}
			return ""
		}
		return nil
	}
}

func WithAuth(auth Auth) SshHandlerOption {
	return func(handler *SshHandler) error {
		for n, option := range []SshHandlerOption{
			WithAuthHostKeys(auth),
			WithAuthPublicKey(auth),
			WithAuthPassword(auth),
			WithAuthKeyboardInteractive(auth),
		} {
			err := option(handler)
			if err != nil {
				return fmt.Errorf("auth option %d: %v", n, err)
			}
		}
		return nil
	}
}
func WithAuthHostKeys(auth AuthHostKeys) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.AuthHostKeys = auth
		hostKeys, err := auth.SshAuthHostKeys(handler)
		if err != nil {
			return err
		}
		for n, hostKey := range hostKeys {
			private, err := ssh.ParsePrivateKey(hostKey)
			if err != nil {
				return fmt.Errorf("parsing hostkey %d: %v", n, err)
			}
			handler.AddHostKey(private)
		}
		return nil
	}
}
func WithAuthPublicKey(auth AuthPublicKey) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.AuthPublicKey = auth
		handler.PublicKeyCallback =
			func(c ssh.ConnMetadata, pubkey ssh.PublicKey) (*ssh.Permissions, error) {
				err := handler.SshAuthPublicKey(handler, c, pubkey)
				if err != nil {
					err = fmt.Errorf("auth public key: %v", err)
					handler.Warn(err)
					return nil, err
				}
				return &ssh.Permissions{}, nil
			}
		return nil
	}
}
func WithAuthPassword(auth AuthPassword) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.AuthPassword = auth
		handler.PasswordCallback =
			func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				err := handler.SshAuthPassword(handler.Context, c, pass)
				if err != nil {
					err = fmt.Errorf("auth password: %v", err)
					handler.Warn(err)
					return nil, err
				}
				return &ssh.Permissions{}, nil
			}
		return nil
	}
}
func WithAuthKeyboardInteractive(auth AuthKeyboardInteractive) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.AuthKeyboardInteractive = auth
		handler.ServerConfig.KeyboardInteractiveCallback =
			func(
				conn ssh.ConnMetadata,
				client ssh.KeyboardInteractiveChallenge,
			) (*ssh.Permissions, error) {
				err := handler.SshAuthKeyboardInteractive(handler, conn, client)
				if err != nil {
					err = fmt.Errorf("auth keyboard interactive: %v", err)
					handler.Warn(err)
					return nil, err
				}
				return &ssh.Permissions{}, err
			}
		return nil
	}
}

func WithGlobalRequest(request GlobalRequest) SshHandlerOption {
	return func(handler *SshHandler) error {
		for n, option := range []SshHandlerOption{
			WithGlobalRequestTcpipForward(request),
			WithGlobalRequestCancelTcpipForward(request),
			WithGlobalRequestCustom(request),
		} {
			if err := option(handler); err != nil {
				return fmt.Errorf("global request %d: %v", n, err)
			}
		}
		return nil
	}
}
func WithGlobalRequestTcpipForward(request GlobalRequestTcpipForward) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.GlobalRequestTcpipForward = request
		return nil
	}
}
func WithGlobalRequestCancelTcpipForward(request GlobalRequestCancelTcpipForward) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.GlobalRequestCancelTcpipForward = request
		return nil
	}
}
func WithGlobalRequestCustom(request GlobalRequestCustom) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.GlobalRequestCustom = request
		return nil
	}
}

func WithChannelSession(channel ChannelSession) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.ChannelSession = channel
		for n, option := range []SshHandlerOption{
			WithRequestPty(channel),
			WithRequestEnv(channel),
			WithRequestShell(channel),
			WithRequestExec(channel),
			WithRequestSubsystem(channel),
			WithRequestWindowChange(channel),
		} {
			if err := option(handler); err != nil {
				return fmt.Errorf("session channel option %d: %v", n, err)
			}
		}
		return nil
	}
}
func WithChannelDirectTcpip(channel ChannelDirectTcpip) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.ChannelDirectTcpip = channel
		return nil
	}
}
func WithChannelForwardedTcpip(channel ChannelForwardedTcpip) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.ChannelForwardedTcpip = channel
		return nil
	}
}
func WithChannelX11(channel ChannelX11) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.ChannelX11 = channel
		return WithRequestX11(channel)(handler)
	}
}
func WithChannelCustom(channel ChannelCustom) SshHandlerOption {
	return func(handler *SshHandler) error {
		handler.ChannelCustom = channel
		return WithRequestCustom(channel)(handler)
	}
}

func WithRequestPty(request RequestPty) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestPty = request; return nil }
}
func WithRequestX11(request RequestX11) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestX11 = request; return nil }
}
func WithRequestEnv(request RequestEnv) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestEnv = request; return nil }
}
func WithRequestShell(request RequestShell) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestShell = request; return nil }
}
func WithRequestExec(request RequestExec) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestExec = request; return nil }
}
func WithRequestSubsystem(request RequestSubsystem) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestSubsystem = request; return nil }
}
func WithRequestWindowChange(request RequestWindowChange) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestWindowChange = request; return nil }
}
func WithRequestSignal(request RequestSignal) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestSignal = request; return nil }
}
func WithRequestXonXoff(request RequestXonXoff) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestXonXoff = request; return nil }
}
func WithRequestBreak(request RequestBreak) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestBreak = request; return nil }
}
func WithRequestCustom(request RequestCustom) SshHandlerOption {
	return func(handler *SshHandler) error { handler.RequestCustom = request; return nil }
}
