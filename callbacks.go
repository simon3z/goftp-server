package server

import (
	"fmt"
	"log"
)

type ServerCallbacks interface {
	ConnectionEstabilished(*Conn)
	ConnectionTerminated(*Conn)
	ConnectionFailed(*Conn, error)
	UserAuthentication(*Conn, string, bool, error)
	UpgradingToTLS(*Conn, error)
	ActiveDataTransfer(*Conn, string, int, error)
	PassiveDataTransfer(*Conn, string, int, error)
	ReceivingCommand(*Conn, string, string)
	SendingResponse(*Conn, int, string)
	DirectoryCreated(*Conn, string, error)
	DirectoryDeleted(*Conn, string, error)
	FileReceived(*Conn, string, int64, error)
	FileDeleted(*Conn, string, error)
}

type DefaultCallbacks struct {
}

func NewDefaultCallbacks() *DefaultCallbacks {
	return &DefaultCallbacks{}
}

func (c *DefaultCallbacks) PrintConnMessage(conn *Conn, format string, v ...interface{}) {
	log.Printf("%s   %s", conn.SessionID(), fmt.Sprintf(format, v...))
}

func (c *DefaultCallbacks) ConnectionEstabilished(conn *Conn) {
	c.PrintConnMessage(conn, "Connection Established")
}

func (c *DefaultCallbacks) ConnectionTerminated(conn *Conn) {
	c.PrintConnMessage(conn, "Connection Terminated")
}

func (c *DefaultCallbacks) ConnectionFailed(conn *Conn, err error) {
	c.PrintConnMessage(conn, "Connection Failed:", err)
}

func (c *DefaultCallbacks) UserAuthentication(conn *Conn, user string, ok bool, err error) {
}

func (c *DefaultCallbacks) UpgradingToTLS(conn *Conn, err error) {
	if err == nil {
		c.PrintConnMessage(conn, "Connection TLS Upgrade Succeeded")
	} else {
		c.PrintConnMessage(conn, "Connection TLS Upgrade Failed:", err)
	}
}

func (c *DefaultCallbacks) ActiveDataTransfer(conn *Conn, host string, port int, err error) {
}

func (c *DefaultCallbacks) PassiveDataTransfer(conn *Conn, host string, port int, err error) {
}

func (c *DefaultCallbacks) ReceivingCommand(conn *Conn, command string, parameters string) {
	if command == "PASS" {
		log.Printf("%s > PASS ****", conn.SessionID())
	} else {
		log.Printf("%s > %s %s", conn.SessionID(), command, parameters)
	}
}

func (c *DefaultCallbacks) SendingResponse(conn *Conn, code int, message string) {
	log.Printf("%s < %d %s", conn.SessionID(), code, message)
}

func (c *DefaultCallbacks) DirectoryCreated(conn *Conn, path string, err error) {
}

func (c *DefaultCallbacks) DirectoryDeleted(conn *Conn, path string, err error) {
}

func (c *DefaultCallbacks) FileReceived(conn *Conn, path string, bytes int64, err error) {
}

func (c *DefaultCallbacks) FileDeleted(conn *Conn, path string, err error) {
}
