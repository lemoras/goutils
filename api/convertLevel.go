package api

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

func GetRoleLevel(roleId int) int {
	roleLevel, err := strconv.Atoi((fmt.Sprintf("%c", fmt.Sprint(roleId)[0])))
	if err != nil {
		log.Fatal(err)
	}
	return roleLevel
}

func GetProjectId(projectInfo string) int {
	projectId, err := strconv.Atoi(strings.Trim(strings.Split(projectInfo, ":")[0], " "))
	if err != nil {
		log.Fatal(err)
	}
	return projectId
}
