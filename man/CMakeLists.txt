#
#  netdiscover - An active/passive address reconnaissance tool
#
#  Copyright (C) 2013 Alexey Shvetsov <alexxy@gentoo.org
#
#  This file is part of netdiscover.
#
#  netdiscover is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  netdiscover is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with netdiscover.  If not, see <http://www.gnu.org/licenses/>.
#

install(DIRECTORY . DESTINATION ${MAN_INSTALL_DIR}
	COMPONENT data
	PATTERN "Makefile*" EXCLUDE
	PATTERN "CMake*" EXCLUDE
	PATTERN "cmake*" EXCLUDE
	PATTERN ".gitignore" EXCLUDE
	)
