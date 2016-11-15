/*
http://tools.ietf.org/html/rfc959

http://www.faqs.org/rfcs/rfc2389.html
http://www.faqs.org/rfcs/rfc959.html

http://tools.ietf.org/html/rfc2428
*/
package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"log"
)

type Command interface {
	IsExtend() bool
	RequireParam() bool
	RequireAuth() bool
	Execute(*Conn, string)
}

const (
	CMD_NONE = 0
	CMD_AUTH = 1 << iota
	CMD_PARM = 1 << iota
	CMD_ISEX = 1 << iota
)

type commandMap map[string]Command

var (
	commands = commandMap{
		"ADAT": commandAdat{NewCommand(CMD_AUTH | CMD_PARM)},
		"ALLO": commandAllo{NewCommand(CMD_NONE)},
		"APPE": commandAppe{NewCommand(CMD_AUTH)},
		"AUTH": commandAuth{NewCommand(CMD_PARM)},
		"CDUP": commandCdup{NewCommand(CMD_AUTH)},
		"CWD":  commandCwd{NewCommand(CMD_AUTH | CMD_PARM)},
		"CCC":  commandCcc{NewCommand(CMD_AUTH | CMD_PARM)},
		"CONF": commandConf{NewCommand(CMD_AUTH | CMD_PARM)},
		"DELE": commandDele{NewCommand(CMD_AUTH | CMD_PARM)},
		"ENC":  commandEnc{NewCommand(CMD_AUTH | CMD_PARM)},
		"EPRT": commandEprt{NewCommand(CMD_AUTH | CMD_PARM | CMD_ISEX)},
		"EPSV": commandEpsv{NewCommand(CMD_AUTH | CMD_ISEX)},
		"FEAT": commandFeat{NewCommand(CMD_NONE)},
		"LIST": commandList{NewCommand(CMD_AUTH)},
		"NLST": commandNlst{NewCommand(CMD_AUTH)},
		"MDTM": commandMdtm{NewCommand(CMD_AUTH | CMD_PARM)},
		"MIC":  commandMic{NewCommand(CMD_AUTH | CMD_PARM)},
		"MKD":  commandMkd{NewCommand(CMD_AUTH | CMD_PARM)},
		"MODE": commandMode{NewCommand(CMD_AUTH | CMD_PARM)},
		"NOOP": commandNoop{NewCommand(CMD_NONE)},
		"OPTS": commandOpts{NewCommand(CMD_NONE)},
		"PASS": commandPass{NewCommand(CMD_PARM)},
		"PASV": commandPasv{NewCommand(CMD_AUTH)},
		"PBSZ": commandPbsz{NewCommand(CMD_AUTH | CMD_PARM)},
		"PORT": commandPort{NewCommand(CMD_AUTH | CMD_PARM)},
		"PROT": commandProt{NewCommand(CMD_AUTH | CMD_PARM)},
		"PWD":  commandPwd{NewCommand(CMD_AUTH)},
		"QUIT": commandQuit{NewCommand(CMD_NONE)},
		"RETR": commandRetr{NewCommand(CMD_AUTH | CMD_PARM)},
		"REST": commandRest{NewCommand(CMD_AUTH | CMD_PARM)},
		"RNFR": commandRnfr{NewCommand(CMD_AUTH | CMD_PARM)},
		"RNTO": commandRnto{NewCommand(CMD_AUTH | CMD_PARM)},
		"RMD":  commandRmd{NewCommand(CMD_AUTH | CMD_PARM)},
		"SIZE": commandSize{NewCommand(CMD_AUTH | CMD_PARM)},
		"STOR": commandStor{NewCommand(CMD_AUTH | CMD_PARM)},
		"STRU": commandStru{NewCommand(CMD_AUTH | CMD_PARM)},
		"SYST": commandSyst{NewCommand(CMD_AUTH)},
		"TYPE": commandType{NewCommand(CMD_AUTH)},
		"USER": commandUser{NewCommand(CMD_PARM)},
		"XCUP": commandCdup{NewCommand(CMD_AUTH)},
		"XCWD": commandCwd{NewCommand(CMD_AUTH | CMD_PARM)},
		"XPWD": commandPwd{NewCommand(CMD_AUTH)},
		"XRMD": commandRmd{NewCommand(CMD_AUTH | CMD_PARM)},
	}
)

type commandBase struct {
	requireAuth  bool
	isExtend     bool
	requireParam bool
}

func NewCommand(opts int) *commandBase {
	return &commandBase{
		requireAuth:  (opts & CMD_AUTH) == CMD_AUTH,
		isExtend:     (opts & CMD_ISEX) == CMD_ISEX,
		requireParam: (opts & CMD_PARM) == CMD_PARM,
	}
}

func (cmd commandBase) RequireAuth() bool {
	return cmd.requireAuth
}

func (cmd commandBase) IsExtend() bool {
	return cmd.isExtend
}

func (cmd commandBase) RequireParam() bool {
	return cmd.requireParam
}

// commandAllo responds to the ALLO FTP command.
//
// This is essentially a ping from the client so we just respond with an
// basic OK message.
type commandAllo struct { *commandBase }

func (cmd commandAllo) Execute(conn *Conn, param string) {
	conn.writeMessage(202, "Obsolete")
}

type commandAppe struct { *commandBase }

func (cmd commandAppe) Execute(conn *Conn, param string) {
	conn.appendData = true
	conn.writeMessage(202, "Obsolete")
}

type commandOpts struct { *commandBase }

func (cmd commandOpts) Execute(conn *Conn, param string) {
	parts := strings.Fields(param)
	if len(parts) != 2 {
		conn.writeMessage(550, "Unknow params")
		return
	}
	if strings.ToUpper(parts[0]) != "UTF8" {
		conn.writeMessage(550, "Unknow params")
		return
	}

	if strings.ToUpper(parts[1]) == "ON" {
		conn.writeMessage(200, "UTF8 mode enabled")
	} else {
		conn.writeMessage(550, "Unsupported non-utf8 mode")
	}
}

type commandFeat struct { *commandBase }

var (
	feats    = "211-Extensions supported:\n%s211 END"
	featCmds = ""
)

func init() {
	for k, v := range commands {
		if v.IsExtend() {
			featCmds = featCmds + " " + k + "\n"
		}
	}
}

func (cmd commandFeat) Execute(conn *Conn, param string) {
	if conn.tlsConfig != nil {
		featCmds += " AUTH TLS\n PBSZ\n PROT\n"
	}
	conn.writeMessage(211, fmt.Sprintf(feats, featCmds))
}

// cmdCdup responds to the CDUP FTP command.
//
// Allows the client change their current directory to the parent.
type commandCdup struct { *commandBase }

func (cmd commandCdup) Execute(conn *Conn, param string) {
	otherCmd := &commandCwd{}
	otherCmd.Execute(conn, "..")
}

// commandCwd responds to the CWD FTP command. It allows the client to change the
// current working directory.
type commandCwd struct { *commandBase }

func (cmd commandCwd) Execute(conn *Conn, param string) {
	path := conn.buildPath(param)
	err := conn.driver.ChangeDir(path)
	if err == nil {
		conn.namePrefix = path
		conn.writeMessage(250, "Directory changed to "+path)
	} else {
		conn.writeMessage(550, fmt.Sprintf("Directory change to %s failed: %s", path, err))
	}
}

// commandDele responds to the DELE FTP command. It allows the client to delete
// a file
type commandDele struct { *commandBase }

func (cmd commandDele) Execute(conn *Conn, param string) {
	path := conn.buildPath(param)
	err := conn.driver.DeleteFile(path)
	if err == nil {
		conn.writeMessage(250, "File deleted")
	} else {
		conn.writeMessage(550, fmt.Sprintf("File delete failed: %s", err))
	}
}

// commandEprt responds to the EPRT FTP command. It allows the client to
// request an active data socket with more options than the original PORT
// command. It mainly adds ipv6 support.
type commandEprt struct { *commandBase }

func (cmd commandEprt) Execute(conn *Conn, param string) {
	delim := string(param[0:1])
	parts := strings.Split(param, delim)

	host := parts[2]

	addressFamily, err := strconv.Atoi(parts[1])
	if err != nil || (addressFamily != 1 && addressFamily != 2) {
		conn.writeMessage(522, "Network protocol not supported, use (1,2)")
		return
	}

	port, err := strconv.Atoi(parts[3])
	if err != nil {
		conn.writeMessage(522, fmt.Sprintf("Port format not supported (%s)", port))
		return
	}

	socket, err := newActiveSocket(host, port, conn.logger)
	if err != nil {
		conn.writeMessage(425, "Data connection failed")
		return
	}

	conn.dataConn = socket
	conn.writeMessage(200, fmt.Sprintf("Connection established (%d)", port))
}

// commandEpsv responds to the EPSV FTP command. It allows the client to
// request a passive data socket with more options than the original PASV
// command. It mainly adds ipv6 support, although we don't support that yet.
type commandEpsv struct { *commandBase }

func (cmd commandEpsv) Execute(conn *Conn, param string) {
	addr := conn.passiveListenIP()

	lastIdx := strings.LastIndex(addr, ":")
	if lastIdx <= 0 {
		conn.writeMessage(425, "Data connection failed")
		return
	}

	socket, err := newPassiveSocket(addr[:lastIdx], conn.PassivePort(), conn.logger, conn.tlsConfig)
	if err != nil {
		log.Println(err)
		conn.writeMessage(425, "Data connection failed")
		return
	}

	conn.dataConn = socket
	conn.writeMessage(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", socket.Port()))
}

// commandList responds to the LIST FTP command. It allows the client to retreive
// a detailed listing of the contents of a directory.
type commandList struct { *commandBase }

func (cmd commandList) Execute(conn *Conn, param string) {
	conn.writeMessage(150, "Opening ASCII mode data connection for file list")
	var fpath string
	if len(param) == 0 {
		fpath = param
	} else {
		fields := strings.Fields(param)
		for _, field := range fields {
			if strings.HasPrefix(field, "-") {
				//TODO: currently ignore all the flag
				//fpath = conn.namePrefix
			} else {
				fpath = field
			}
		}
	}

	path := conn.buildPath(fpath)
	info, err := conn.driver.Stat(path)
	if err != nil {
		conn.writeMessage(550, err.Error())
		return
	}

	if !info.IsDir() {
		conn.logger.Printf("%s is not a dir.\n", path)
		return
	}
	var files []FileInfo
	err = conn.driver.ListDir(path, func(f FileInfo) error {
		files = append(files, f)
		return nil
	})
	if err != nil {
		conn.writeMessage(550, err.Error())
		return
	}

	conn.sendOutofbandData(listFormatter(files).Detailed())
}

// commandNlst responds to the NLST FTP command. It allows the client to
// retreive a list of filenames in the current directory.
type commandNlst struct { *commandBase }

func (cmd commandNlst) Execute(conn *Conn, param string) {
	conn.writeMessage(150, "Opening ASCII mode data connection for file list")
	var fpath string
	if len(param) == 0 {
		fpath = param
	} else {
		fields := strings.Fields(param)
		for _, field := range fields {
			if strings.HasPrefix(field, "-") {
				//TODO: currently ignore all the flag
				//fpath = conn.namePrefix
			} else {
				fpath = field
			}
		}
	}

	path := conn.buildPath(fpath)
	info, err := conn.driver.Stat(path)
	if err != nil {
		conn.writeMessage(550, err.Error())
		return
	}
	if !info.IsDir() {
		// TODO: should we show the file description?
		return
	}

	var files []FileInfo
	err = conn.driver.ListDir(path, func(f FileInfo) error {
		files = append(files, f)
		return nil
	})
	if err != nil {
		conn.writeMessage(550, err.Error())
		return
	}
	conn.sendOutofbandData(listFormatter(files).Short())
}

// commandMdtm responds to the MDTM FTP command. It allows the client to
// retreive the last modified time of a file.
type commandMdtm struct { *commandBase }

func (cmd commandMdtm) Execute(conn *Conn, param string) {
	path := conn.buildPath(param)
	stat, err := conn.driver.Stat(path)
	if err == nil {
		conn.writeMessage(213, stat.ModTime().Format("20060102150405"))
	} else {
		conn.writeMessage(450, "File not available")
	}
}

// commandMkd responds to the MKD FTP command. It allows the client to create
// a new directory
type commandMkd struct { *commandBase }

func (cmd commandMkd) Execute(conn *Conn, param string) {
	path := conn.buildPath(param)
	err := conn.driver.MakeDir(path)
	if err == nil {
		conn.writeMessage(257, "Directory created")
	} else {
		conn.writeMessage(550, fmt.Sprintf("Action not taken: %s", err))
	}
}

// cmdMode responds to the MODE FTP command.
//
// the original FTP spec had various options for hosts to negotiate how data
// would be sent over the data socket, In reality these days (S)tream mode
// is all that is used for the mode - data is just streamed down the data
// socket unchanged.
type commandMode struct { *commandBase }

func (cmd commandMode) Execute(conn *Conn, param string) {
	if strings.ToUpper(param) == "S" {
		conn.writeMessage(200, "OK")
	} else {
		conn.writeMessage(504, "MODE is an obsolete command")
	}
}

// cmdNoop responds to the NOOP FTP command.
//
// This is essentially a ping from the client so we just respond with an
// basic 200 message.
type commandNoop struct { *commandBase }

func (cmd commandNoop) Execute(conn *Conn, param string) {
	conn.writeMessage(200, "OK")
}

// commandPass respond to the PASS FTP command by asking the driver if the
// supplied username and password are valid
type commandPass struct { *commandBase }

func (cmd commandPass) Execute(conn *Conn, param string) {
	ok, err := conn.server.Auth.CheckPasswd(conn.reqUser, param)
	if err != nil {
		conn.writeMessage(550, "Checking password error")
		return
	}

	if ok {
		conn.user = conn.reqUser
		conn.reqUser = ""
		conn.writeMessage(230, "Password ok, continue")
	} else {
		conn.writeMessage(530, "Incorrect password, not logged in")
	}
}

// commandPasv responds to the PASV FTP command.
//
// The client is requesting us to open a new TCP listing socket and wait for them
// to connect to it.
type commandPasv struct { *commandBase }

func (cmd commandPasv) Execute(conn *Conn, param string) {
	listenIP := conn.passiveListenIP()

	socket, err := newPassiveSocket(listenIP, conn.PassivePort(), conn.logger, conn.tlsConfig)
	if err != nil {
		conn.writeMessage(425, "Data connection failed")
		return
	}

	conn.dataConn = socket

	addr := net.ParseIP(listenIP)
	target := fmt.Sprintf("(%d,%d,%d,%d,%d,%d)", addr[0], addr[1], addr[2], addr[3], socket.Port() >> 8, socket.Port() & 0xFF)

	conn.writeMessage(227, fmt.Sprintf("Entering Passive Mode %s", target))
}

// commandPort responds to the PORT FTP command.
//
// The client has opened a listening socket for sending out of band data and
// is requesting that we connect to it
type commandPort struct { *commandBase }

func (cmd commandPort) Execute(conn *Conn, param string) {
	parts := strings.Split(param, ",")

	host := strings.Join(parts[:4], ".")

	portFirstWord, err := strconv.Atoi(parts[4])
	if err != nil {
		conn.writeMessage(522, fmt.Sprintf("Port format not supported (%s)", portFirstWord))
		return
	}

	portSecondWord, err := strconv.Atoi(parts[5])
	if err != nil {
		conn.writeMessage(522, fmt.Sprintf("Port format not supported (%s)", portSecondWord))
		return
	}

	port := portFirstWord<<8 + portSecondWord

	socket, err := newActiveSocket(host, port, conn.logger)
	if err != nil {
		conn.writeMessage(425, "Data connection failed")
		return
	}

	conn.dataConn = socket
	conn.writeMessage(200, fmt.Sprintf("Connection established (%d)", port))
}

// commandPwd responds to the PWD FTP command.
//
// Tells the client what the current working directory is.
type commandPwd struct { *commandBase }

func (cmd commandPwd) Execute(conn *Conn, param string) {
	conn.writeMessage(257, "\""+conn.namePrefix+"\" is the current directory")
}

// CommandQuit responds to the QUIT FTP command. The client has requested the
// connection be closed.
type commandQuit struct { *commandBase }

func (cmd commandQuit) Execute(conn *Conn, param string) {
	conn.writeMessage(221, "Goodbye")
	conn.Close()
}

// commandRetr responds to the RETR FTP command. It allows the client to
// download a file.
type commandRetr struct { *commandBase }

func (cmd commandRetr) Execute(conn *Conn, param string) {
	path := conn.buildPath(param)
	defer func() {
		conn.lastFilePos = 0
	}()
	bytes, data, err := conn.driver.GetFile(path, conn.lastFilePos)
	if err == nil {
		defer data.Close()
		conn.writeMessage(150, fmt.Sprintf("Data transfer starting %v bytes", bytes))
		err = conn.sendOutofBandDataWriter(data)
	} else {
		conn.writeMessage(551, "File not available")
	}
}

type commandRest struct { *commandBase }

func (cmd commandRest) Execute(conn *Conn, param string) {
	var err error
	conn.lastFilePos, err = strconv.ParseInt(param, 10, 64)
	if err != nil {
		conn.writeMessage(551, "File not available")
		return
	}

	conn.appendData = true

	conn.writeMessage(350, fmt.Sprintf("Start transfer from %s", conn.lastFilePos))
}

// commandRnfr responds to the RNFR FTP command. It's the first of two commands
// required for a client to rename a file.
type commandRnfr struct { *commandBase }

func (cmd commandRnfr) Execute(conn *Conn, param string) {
	conn.renameFrom = conn.buildPath(param)
	conn.writeMessage(350, "Requested file action pending further information.")
}

// cmdRnto responds to the RNTO FTP command. It's the second of two commands
// required for a client to rename a file.
type commandRnto struct { *commandBase }

func (cmd commandRnto) Execute(conn *Conn, param string) {
	toPath := conn.buildPath(param)
	err := conn.driver.Rename(conn.renameFrom, toPath)
	defer func() {
		conn.renameFrom = ""
	}()

	if err == nil {
		conn.writeMessage(250, "File renamed")
	} else {
		conn.writeMessage(550, fmt.Sprintf("Action not taken: %s", err))
	}
}

// cmdRmd responds to the RMD FTP command. It allows the client to delete a
// directory.
type commandRmd struct { *commandBase }

func (cmd commandRmd) Execute(conn *Conn, param string) {
	path := conn.buildPath(param)
	err := conn.driver.DeleteDir(path)
	if err == nil {
		conn.writeMessage(250, "Directory deleted")
	} else {
		conn.writeMessage(550, fmt.Sprintf("Directory delete failed: %s", err))
	}
}

type commandAdat struct {
	*commandBase
}

func (cmd commandAdat) Execute(conn *Conn, param string) {
	conn.writeMessage(550, "Action not taken")
}

type commandAuth struct { *commandBase }

func (cmd commandAuth) Execute(conn *Conn, param string) {
	log.Println(param, conn)
	if param == "TLS" && conn.tlsConfig != nil {
		conn.writeMessage(234, "AUTH command OK")
		err := conn.upgradeToTLS()
		if err != nil {
			conn.logger.Printf("Error upgrading conection to TLS %v", err)
		}
	} else {
		conn.writeMessage(550, "Action not taken")
	}
}

type commandCcc struct { *commandBase }

func (cmd commandCcc) Execute(conn *Conn, param string) {
	conn.writeMessage(550, "Action not taken")
}

type commandEnc struct { *commandBase }

func (cmd commandEnc) Execute(conn *Conn, param string) {
	conn.writeMessage(550, "Action not taken")
}

type commandMic struct { *commandBase }

func (cmd commandMic) Execute(conn *Conn, param string) {
	conn.writeMessage(550, "Action not taken")
}

type commandPbsz struct { *commandBase }

func (cmd commandPbsz) Execute(conn *Conn, param string) {
	if conn.tls && param == "0" {
		conn.writeMessage(200, "OK")
	} else {
		conn.writeMessage(550, "Action not taken")
	}
}

type commandProt struct { *commandBase }

func (cmd commandProt) Execute(conn *Conn, param string) {
	if conn.tls && param == "P" {
		conn.writeMessage(200, "OK")
	} else if conn.tls {
		conn.writeMessage(536, "Only P level is supported")
	} else {
		conn.writeMessage(550, "Action not taken")
	}
}

type commandConf struct { *commandBase }

func (cmd commandConf) Execute(conn *Conn, param string) {
	conn.writeMessage(550, "Action not taken")
}

// commandSize responds to the SIZE FTP command. It returns the size of the
// requested path in bytes.
type commandSize struct { *commandBase }

func (cmd commandSize) Execute(conn *Conn, param string) {
	path := conn.buildPath(param)
	stat, err := conn.driver.Stat(path)
	if err != nil {
		log.Printf("Size: error(%s)", err)
		conn.writeMessage(450, fmt.Sprintf("path %s not found", path))
	} else {
		conn.writeMessage(213, strconv.Itoa(int(stat.Size())))
	}
}

// commandStor responds to the STOR FTP command. It allows the user to upload a
// new file.
type commandStor struct { *commandBase }

func (cmd commandStor) Execute(conn *Conn, param string) {
	targetPath := conn.buildPath(param)
	conn.writeMessage(150, "Data transfer starting")

	defer func() {
		conn.appendData = false
	}()

	bytes, err := conn.driver.PutFile(targetPath, conn.dataConn, conn.appendData)
	if err == nil {
		msg := "OK, received " + strconv.Itoa(int(bytes)) + " bytes"
		conn.writeMessage(226, msg)
	} else {
		conn.writeMessage(553, fmt.Sprintf("error during transfer: %s", err))
	}
}

// commandStru responds to the STRU FTP command.
//
// like the MODE and TYPE commands, stru[cture] dates back to a time when the
// FTP protocol was more aware of the content of the files it was transferring,
// and would sometimes be expected to translate things like EOL markers on the
// fly.
//
// These days files are sent unmodified, and F(ile) mode is the only one we
// really need to support.
type commandStru struct { *commandBase }

func (cmd commandStru) Execute(conn *Conn, param string) {
	if strings.ToUpper(param) == "F" {
		conn.writeMessage(200, "OK")
	} else {
		conn.writeMessage(504, "STRU is an obsolete command")
	}
}

// commandSyst responds to the SYST FTP command by providing a canned response.
type commandSyst struct { *commandBase }

func (cmd commandSyst) Execute(conn *Conn, param string) {
	conn.writeMessage(215, "UNIX Type: L8")
}

// commandType responds to the TYPE FTP command.
//
//  like the MODE and STRU commands, TYPE dates back to a time when the FTP
//  protocol was more aware of the content of the files it was transferring, and
//  would sometimes be expected to translate things like EOL markers on the fly.
//
//  Valid options were A(SCII), I(mage), E(BCDIC) or LN (for local type). Since
//  we plan to just accept bytes from the client unchanged, I think Image mode is
//  adequate. The RFC requires we accept ASCII mode however, so accept it, but
//  ignore it.
type commandType struct { *commandBase }

func (cmd commandType) Execute(conn *Conn, param string) {
	if strings.ToUpper(param) == "A" {
		conn.writeMessage(200, "Type set to ASCII")
	} else if strings.ToUpper(param) == "I" {
		conn.writeMessage(200, "Type set to binary")
	} else {
		conn.writeMessage(500, "Invalid type")
	}
}

// commandUser responds to the USER FTP command by asking for the password
type commandUser struct { *commandBase }

func (cmd commandUser) Execute(conn *Conn, param string) {
	conn.reqUser = param
	conn.writeMessage(331, "User name ok, password required")
}
