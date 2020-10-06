package main

import (
	"github.com/bombsimon/logrusr"
	"github.com/sirupsen/logrus"
)

func main() {
	log := logrusr.NewLogger(logrus.New())
	log.Info("test123")
}
