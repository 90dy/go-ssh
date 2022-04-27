package ssh

import (
	. "context"

	"golang.org/x/crypto/ssh"
)

type Metadata = ssh.ConnMetadata
type PublicKey = ssh.PublicKey
type Challenge = ssh.KeyboardInteractiveChallenge
type Channel = ssh.Channel

var Unmarshal = ssh.Unmarshal

type Conn interface {
	Banner
	Auth
	GlobalRequest
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

type Banner interface {
	SshBanner(Context, Metadata) string
}

type Auth interface {
	AuthHostKeys
	AuthPublicKey
	AuthPassword
	AuthKeyboardInteractive
	AuthHostBased
}
type AuthHostKeys interface {
	SshAuthHostKeys(Context) ([][]byte, error)
}
type AuthPublicKey interface {
	SshAuthPublicKey(Context, Metadata, PublicKey) error
}
type AuthPassword interface {
	SshAuthPassword(Context, Metadata, []byte) error
}
type AuthKeyboardInteractive interface {
	SshAuthKeyboardInteractive(Context, Metadata, Challenge) error
}
type AuthHostBased interface {
	// TODO: HostBased
	// cf. https://tools.ietf.org/html/rfc4252#section-9
	// HostBased(Context, ...)
}

type GlobalRequest interface {
	GlobalRequestTcpipForward
	GlobalRequestCancelTcpipForward
	GlobalRequestCustom
}

type GlobalRequestTcpipForwardPayload struct {
	Address string
	Port    uint32
}
type GlobalRequestCancelTcpipForwardPayload struct {
	Address string
	Port    uint32
}
type GlobalRequestCustomPayload struct {
	Type string
	Data []byte
}

type GlobalRequestTcpipForward interface {
	SshGlobalRequestTcpipForward(Context, Metadata, *GlobalRequestTcpipForwardPayload) error
}
type GlobalRequestCancelTcpipForward interface {
	SshGlobalRequestCancelTcpipForward(Context, Metadata, *GlobalRequestCancelTcpipForwardPayload) error
}
type GlobalRequestCustom interface {
	SshGlobalRequestCustom(Context, Metadata, *GlobalRequestCustomPayload) error
}

type ChannelForwardedTcpipPayload struct {
	Address    string
	Port       uint32
	OriginIP   string
	OriginPort uint32
}
type ChannelX11Payload struct {
	SenderChannel string
	InitWinSize   uint32
	OriginAddr    string
	OriginPort    uint32
}
type ChannelDirectTcpipPayload struct {
	Host       string
	Port       uint32
	OriginIP   string
	OriginPort uint32
}
type ChannelSessionPayload struct {
	SenderChannel string
	InitWinSize   uint32
	MaxPacketSize uint32
}
type ChannelCustomPayload struct {
	Type string
	Data []byte
}

type ChannelSession interface {
	SshChannelSession(Context, Metadata, Channel, *ChannelSessionPayload) error
	RequestPty
	RequestEnv
	RequestShell
	RequestExec
	RequestSubsystem
	RequestWindowChange
}
type ChannelDirectTcpip interface {
	SshChannelDirectTcpip(Context, Metadata, Channel, *ChannelDirectTcpipPayload) error
}
type ChannelForwardedTcpip interface {
	SshChannelForwardedTcpip(Context, Metadata, Channel, *ChannelForwardedTcpipPayload) error
}
type ChannelX11 interface {
	SshChannelX11(Context, Metadata, Channel, *ChannelX11Payload) error
	RequestX11
	// TODO: check rfc x11
}
type ChannelCustom interface {
	SshChannelCustom(Context, Metadata, Channel, *ChannelCustomPayload) error
	RequestCustom
}

type RequestPtyPayload struct {
	Term   string
	Width  string
	Height string
}
type RequestX11Payload struct {
	AuthProto    string
	AuthCookie   string
	ScreenNumber uint32
}
type RequestEnvPayload struct {
	Name  string
	Value string
}
type RequestShellPayload struct{}
type RequestExecPayload struct {
	Command string
}
type RequestSubsystemPayload struct {
	Name string
}
type RequestWindowChangePayload struct {
	Width  uint32
	Height uint32
}
type RequestSignalPayload struct {
	Signal string
}
type RequestXonXoffPayload struct {
	ClientCanDo bool
}
type RequestBreakPayload struct {
	Milliseconds uint32
}
type RequestCustomPayload struct {
	Type string
	Data []byte
}
type RequestExitStatusPayload struct {
	Status uint32
}

type RequestPty interface {
	SshRequestPty(Context, Metadata, Channel, *RequestPtyPayload) error
}
type RequestX11 interface {
	SshRequestX11(Context, Metadata, Channel, *RequestX11Payload) error
}
type RequestEnv interface {
	SshRequestEnv(Context, Metadata, Channel, *RequestEnvPayload) error
}
type RequestShell interface {
	SshRequestShell(Context, Metadata, Channel, *RequestShellPayload) (uint32, error)
}
type RequestExec interface {
	SshRequestExec(Context, Metadata, Channel, *RequestExecPayload) (uint32, error)
}
type RequestSubsystem interface {
	SshRequestSubsystem(Context, Metadata, Channel, *RequestSubsystemPayload) (uint32, error)
}
type RequestWindowChange interface {
	SshRequestWindowChange(Context, Metadata, Channel, *RequestWindowChangePayload) error
}
type RequestSignal interface {
	SshRequestSignal(Context, Metadata, Channel, *RequestSignalPayload) error
}
type RequestXonXoff interface {
	SshRequestXonXoff(Context, Metadata, Channel, *RequestXonXoffPayload) error
}
type RequestBreak interface {
	SshRequestBreak(Context, Metadata, Channel, *RequestBreakPayload) error
}
type RequestCustom interface {
	SshRequestCustom(Context, Metadata, Channel, *RequestCustomPayload) error
}
type RequestExitStatus interface {
	SshRequestExitStatus(Context, Metadata, Channel, *RequestExitStatusPayload) error
}
