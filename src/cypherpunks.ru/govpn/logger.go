/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2016 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package govpn

import (
	"log"
	"log/syslog"
)

var (
	sysloger *log.Logger
)

// Enable logging to syslog, instead of default stdout log.
func SyslogEnable() {
	var err error
	sysloger, err = syslog.NewLogger(syslog.LOG_INFO, 0)
	if err != nil {
		log.Fatalln(err)
	}
}

// Call either syslog-related logger.Println if SyslogEnabled,
// default log.Println otherwise.
func Println(v ...interface{}) {
	if sysloger == nil {
		log.Println(v...)
	} else {
		sysloger.Println(v...)
	}
}
