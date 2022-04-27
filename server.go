package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"sync"

	. "context"

	"golang.org/x/crypto/ssh"

	"github.com/sirupsen/logrus"
)

type SshServer struct{ SshHandler }

type SshHandler struct {
	Context
	ssh.ServerConfig
	logrus.FieldLogger
	Banner
	AuthHostKeys
	AuthPublicKey
	AuthPassword
	AuthHostBased
	AuthKeyboardInteractive
	GlobalRequestTcpipForward
	GlobalRequestCancelTcpipForward
	GlobalRequestCustom
	ChannelSession
	ChannelDirectTcpip
	ChannelForwardedTcpip
	ChannelX11
	ChannelCustom
	RequestPty
	RequestX11
	RequestEnv
	RequestShell
	RequestExec
	RequestSubsystem
	RequestWindowChange
	RequestSignal
	RequestXonXoff
	RequestBreak
	RequestCustom
}

func NewServer(options ...SshServerOption) (*SshServer, error) {
	server := &SshServer{
		SshHandler{
			Context:     Background(),
			FieldLogger: logrus.StandardLogger(),
		},
	}
	for n, option := range options {
		if err := option(&server.SshHandler); err != nil {
			return nil, fmt.Errorf("option %d: %v", n, err)
		}
	}
	return server, nil
}

func NewHandler(options ...SshHandlerOption) (*SshHandler, error) {
	server, err := NewServer(options...)
	if err != nil {
		return nil, err
	}
	return &server.SshHandler, nil
}

func (server *SshServer) SshListen(ctx Context, listener net.Listener) error {
	server.Debugf("listening to %s", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept conn: %v", err)
		}
		go func() {
			defer conn.Close()
			err := server.SshHandler.Accept(ctx, conn)
			if err != nil {
				server.Warnf("accepting conn: %v", err)
			}
		}()
	}
}

func (handler *SshHandler) Accept(ctx Context, nConn net.Conn) error {
	handler.Debug("accepting conn")
	defer handler.Debug("accepting conn: done")

	metadata, newChannels, globalRequests, err := ssh.NewServerConn(nConn, &handler.ServerConfig)
	if err != nil {
		return fmt.Errorf("handshake: %v", err)
	}

	wg := sync.WaitGroup{}
	defer handler.Debug("wait finished")
	defer wg.Wait()
	defer handler.Debug("wait finished start")

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer handler.recover()

		handler.Debug("handling global requests")
		defer handler.Debug("handling globalRequests: done")

		for request := range globalRequests {
			var err error
			handler.Debugf("handling global request: %s", request.Type)

			switch request.Type {
			case "tcpip-forward":
				if handler.GlobalRequestTcpipForward == nil {
					err = errors.New("not implemented")
					break
				}
				payload := &GlobalRequestTcpipForwardPayload{}
				ssh.Unmarshal(request.Payload, payload)
				err = handler.SshGlobalRequestTcpipForward(ctx, metadata, payload)

			case "cancel-tcpip-forward":
				if handler.GlobalRequestCancelTcpipForward == nil {
					err = errors.New("not implemented")
					break
				}
				payload := &GlobalRequestCancelTcpipForwardPayload{}
				ssh.Unmarshal(request.Payload, payload)
				err = handler.SshGlobalRequestCancelTcpipForward(ctx, metadata, payload)

			default:
				if handler.GlobalRequestCustom == nil {
					err = errors.New("not implemented")
					break
				}
				payload := &GlobalRequestCustomPayload{
					Type: request.Type,
					Data: request.Payload,
				}
				err = handler.SshGlobalRequestCustom(ctx, metadata, payload)
			}

			if err != nil {
				handler.Warnf("global request %s: %v", request.Type, err)
				if request.WantReply {
					request.Reply(false, nil)
				}
			}
			if request.WantReply {
				request.Reply(true, nil)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer handler.recover()

		handler.Debug("handling channels")
		defer handler.Debug("handling channels: done")

		for newChannel := range newChannels {

			chanType := newChannel.ChannelType()
			handler.Debugf("handling channel %s", chanType)

			switch chanType {
			case "session":
				if handler.ChannelSession == nil {
					handler.Debugf("channel %s not implemented", chanType)
					newChannel.Reject(ssh.Prohibited, "not implemented")
					continue
				}
			case "direct-tcpip":
				if handler.ChannelDirectTcpip == nil {
					handler.Debugf("channel %s not implemented", chanType)
					newChannel.Reject(ssh.Prohibited, "not implemented")
					continue
				}
			case "forwarded-tcpip":
				if handler.ChannelForwardedTcpip == nil {
					handler.Debugf("channel %s not implemented", chanType)
					newChannel.Reject(ssh.Prohibited, "not implemented")
					continue
				}
			case "x11":
				if handler.ChannelX11 == nil {
					handler.Debugf("channel %s not implemented", chanType)
					newChannel.Reject(ssh.Prohibited, "not implemented")
					continue
				}
			default:
				if handler.ChannelCustom == nil {
					handler.Debugf("channel %s unknown", chanType)
					newChannel.Reject(ssh.UnknownChannelType, "unknwown channel")
					continue
				}
			}

			channel, requests, err := newChannel.Accept()
			if err != nil {
				handler.Warnf("accepting channel: %v", err)
				continue
			}

			switch newChannel.ChannelType() {
			case "session":
				payload := &ChannelSessionPayload{}
				ssh.Unmarshal(newChannel.ExtraData(), payload)
				err := handler.ChannelSession.SshChannelSession(ctx, metadata, channel, payload)
				if err != nil {
					handler.Warnf("channel session: %v", err.Error())
					io.WriteString(channel.Stderr(), err.Error())
					channel.Close()
					continue
				}

			case "direct-tcpip":
				payload := &ChannelDirectTcpipPayload{}
				ssh.Unmarshal(newChannel.ExtraData(), payload)
				err := handler.ChannelDirectTcpip.SshChannelDirectTcpip(ctx, metadata, channel, payload)
				if err != nil {
					handler.Warnf("%s: %v", err.Error())
					handler.Warnf("channel direct-tcpip: %v", err.Error())
					io.WriteString(channel.Stderr(), err.Error())
					channel.Close()
					continue
				}
				go ssh.DiscardRequests(requests)
				continue

			case "forwarded-tcpip":
				payload := &ChannelForwardedTcpipPayload{}
				ssh.Unmarshal(newChannel.ExtraData(), payload)
				err := handler.ChannelForwardedTcpip.SshChannelForwardedTcpip(ctx, metadata, channel, payload)
				if err != nil {
					handler.Warnf("%s: %v", err.Error())
					handler.Warnf("channel forwarded-tcpip: %v", err.Error())
					io.WriteString(channel.Stderr(), err.Error())
					channel.Close()
					continue
				}
				go ssh.DiscardRequests(requests)
				continue

			case "x11":
				payload := &ChannelX11Payload{}
				ssh.Unmarshal(newChannel.ExtraData(), payload)
				err := handler.ChannelX11.SshChannelX11(ctx, metadata, channel, payload)
				if err != nil {
					handler.Warnf("channel x11: %v", err.Error())
					io.WriteString(channel.Stderr(), err.Error())
					channel.Close()
					continue
				}

			default:
				payload := &ChannelCustomPayload{
					Type: newChannel.ChannelType(),
					Data: newChannel.ExtraData(),
				}
				err := handler.ChannelCustom.SshChannelCustom(ctx, metadata, channel, payload)
				if err != nil {
					handler.Warnf("channel %s: %v", payload.Type, err.Error())
					io.WriteString(channel.Stderr(), err.Error())
					channel.Close()
					continue
				}
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				defer channel.Close()
				defer handler.recover()

				handler.Debug("handling requests")
				defer handler.Debug("handling requests: done")
				for request := range requests {
					var err error
					var status uint32 = 0
					handler.Debugf("handling request: %s", request.Type)

					switch request.Type {
					case "pty-req":
						if handler.RequestPty == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestPtyPayload{}
						ssh.Unmarshal(request.Payload, payload)
						err = handler.RequestPty.SshRequestPty(ctx, metadata, channel, payload)

					case "x11-req":
						if handler.RequestX11 == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestX11Payload{}
						ssh.Unmarshal(request.Payload, payload)
						err = handler.RequestX11.SshRequestX11(ctx, metadata, channel, payload)

					case "env":
						if handler.RequestEnv == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestEnvPayload{}
						ssh.Unmarshal(request.Payload, payload)
						err = handler.RequestEnv.SshRequestEnv(ctx, metadata, channel, payload)

					case "shell":
						if handler.RequestShell == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestShellPayload{}
						status, err = handler.RequestShell.SshRequestShell(ctx, metadata, channel, payload)

					case "exec":
						if handler.RequestExec == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestExecPayload{}
						ssh.Unmarshal(request.Payload, payload)
						status, err = handler.RequestExec.SshRequestExec(ctx, metadata, channel, payload)

					case "subsystem":
						if handler.RequestSubsystem == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestSubsystemPayload{}
						ssh.Unmarshal(request.Payload, payload)
						status, err = handler.RequestSubsystem.SshRequestSubsystem(ctx, metadata, channel, payload)

					case "window-change":
						if handler.RequestWindowChange == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestWindowChangePayload{}
						ssh.Unmarshal(request.Payload, payload)
						err = handler.RequestWindowChange.SshRequestWindowChange(ctx, metadata, channel, payload)

					case "signal":
						if handler.RequestSignal == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestSignalPayload{}
						ssh.Unmarshal(request.Payload, payload)
						err = handler.RequestSignal.SshRequestSignal(ctx, metadata, channel, payload)

					case "xon-xoff":
						if handler.RequestXonXoff == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestXonXoffPayload{}
						ssh.Unmarshal(request.Payload, payload)
						err = handler.RequestXonXoff.SshRequestXonXoff(ctx, metadata, channel, payload)

					case "break":
						if handler.RequestBreak == nil {
							err = errors.New("not implemented")
							break
						}
						payload := &RequestBreakPayload{}
						ssh.Unmarshal(request.Payload, payload)
						err = handler.RequestBreak.SshRequestBreak(ctx, metadata, channel, payload)

					default:
						if handler.RequestCustom == nil {
							err = errors.New("not implemented")
							break
						}
						err = handler.RequestCustom.SshRequestCustom(
							ctx,
							metadata,
							channel,
							&RequestCustomPayload{
								Type: request.Type,
								Data: request.Payload,
							},
						)
					}
					if err != nil {
						handler.Warnf("request %s: %v", request.Type, err)
						if request.WantReply {
							request.Reply(false, nil)
						}
						continue
					}
					if request.WantReply {
						request.Reply(true, nil)
					}
					if status != 0 {
						_, err := channel.SendRequest("exit-status", false, ssh.Marshal(&RequestExitStatusPayload{Status: status}))
						if err != nil {
							handler.Warnf("sending request exit-status: %v", err)
						}
					}
				}
			}()
		}
	}()
	return nil
}

func (handler *SshHandler) recover() {
	if err := recover(); err != nil {
		handler.Errorf("panic %v\r\n%s", err, string(debug.Stack()))
	}
}
