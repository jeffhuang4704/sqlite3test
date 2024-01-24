package main

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

var dbFile_KVStore string = "./kv.db"

func main() {
	err := CreateDatabase(1)
	if err != nil {
		fmt.Println(err)
	}
}

func CreateDatabase(dbType int) error {

	dbFile := dbFile_KVStore

	// err := os.Remove(dbFile)
	// if err != nil {
	// 	fmt.Println(err)
	// 	log.WithFields(log.Fields{"err": err, "dbFile": dbFile}).Debug("searchme, create database failed")
	// }

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer db.Close()

	if err := CreateTables(db, dbType); err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func CreateTables(db *sql.DB, dbType int) error {
	return createKVStoreTables(db)
}

func createKVStoreTables(db *sql.DB) error {

	tb_kvstore := `
    CREATE TABLE IF NOT EXISTS "kvstore" (
		"id"	INTEGER,
		"createdAt"	INTEGER,
		"updatedAt"	INTEGER,
		"kvkey"	TEXT,
		"kvdata"	TEXT,
		"kvdata2" 	BLOB,
		"kvdatamd5"	TEXT,
		"notes"	TEXT,
		PRIMARY KEY("id")
    );
    CREATE INDEX kvstore_kvkey_idx on kvstore (kvkey);
`

	tb_cvedb := `
    CREATE TABLE IF NOT EXISTS "cvedb" (
        "id"	INTEGER,
        "name"	TEXT,
        "json"	TEXT,
        PRIMARY KEY("id")
    );
    CREATE INDEX cvedb_name_idx on cvedb (name);
`

	// data1 => mem_stat
	// data2 => cache_stat
	// data3 => misc_stat
	// bindata1 => prof_allocs
	// bindata2 => prof_heap
	// bindata3 => prof_goroutine

	tb_stats := `
    CREATE TABLE IF NOT EXISTS "stats" (
        "id"	INTEGER,
        "note"	TEXT,
		"pid"   INTEGER,
        "mem_stat"  TEXT,
        "cache_stat"  TEXT,
        "misc_stat"  TEXT,
        "prof_allocs" BLOB,
        "prof_heap" BLOB,
        "prof_goroutine" BLOB,
        "addedTimestamp"	INTEGER,
        PRIMARY KEY("id")
    )
`

	tb_resources := `
    CREATE TABLE IF NOT EXISTS "resources" (
        "resid"	INTEGER,
        "resourceId"	TEXT,
        "resourceType"	INTEGER,
		"workload_namespace"	    TEXT,
		"image_repo"	TEXT,
		"image_tag"	    TEXT,
        "rawJson"	    TEXT,
        "notes"         TEXT,
        PRIMARY KEY("resid")
    );
    CREATE INDEX resources_resourceId_idx on resources (resourceId);
    `

	tb_vul := `
    CREATE TABLE IF NOT EXISTS "vulnerabilities" (
        "id"	        INTEGER,
        "Name"	        TEXT,
        "Score"	        INTEGER,
        "ScoreV3"	    INTEGER,
        "Field5"	    INTEGER,
        "Severity"	    TEXT,
        "PublishedTS"	INTEGER,
        "LastModTS"	    INTEGER,
        "rawJson"	    TEXT,
        PRIMARY KEY("id")
    );
    CREATE INDEX vulnerabilities_name_idx on vulnerabilities (Name);
    `

	tb_vulRes := `
    CREATE TABLE IF NOT EXISTS "vulResources" (
        "vulnerability_id"	INTEGER,
        "resid"	INTEGER
    )
    `

	tb_sessionTmp := `
    CREATE TABLE IF NOT EXISTS "sessionTmpVulnerability" (
        "id"	INTEGER,
        "vulnerability_id"	INTEGER,
        "rawJson"	TEXT,
        PRIMARY KEY("id")
    )
    `

	tb_vulPackages := `
    CREATE TABLE IF NOT EXISTS "vulPackages" (
        "id"	INTEGER,
        "vulnerability_id"	INTEGER,
        "resid"	            INTEGER,
        "packageName" TEXT,
        "rawJson"	TEXT,
        PRIMARY KEY("id")
    )
    `

	tb_sessionsMeta := `
    CREATE TABLE IF NOT EXISTS "sessionsMeta" (
        "id"	INTEGER,
        "create_timestamp"	INTEGER,
        "tablename"	TEXT,
        "identity"	TEXT,
        "request"	TEXT,
        "response"	TEXT,
        PRIMARY KEY("id")
    )
    `

	var tables = []string{tb_kvstore, tb_cvedb, tb_stats, tb_resources, tb_vul, tb_vulRes, tb_sessionTmp, tb_vulPackages, tb_sessionsMeta}

	for _, tbl := range tables {
		if err := ExecuteSQL(db, tbl); err != nil {
			log.WithFields(log.Fields{"err": err, "tbl": tbl}).Debug("searchme, CreateTables() failed")
			return err
		}
	}

	return nil
}

func ExecuteSQL(db *sql.DB, statement string) error {
	if _, err := db.Exec(statement); err != nil {
		return err
	}
	return nil
}


