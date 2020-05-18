"use strict";

const sql = require('mssql');

const config = {
    user: process.env.MSSQL_USER,
    password: process.env.MSSQL_PASSWORD,
    server: process.env.MSSQL_HOST,
    database: process.env.MSSQL_DATABASE,
    port: process.env.MSSQL_PORT,
    pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 5000
    }
};

const sqlpool = {
    query: function (qry, res) {
        let dbConn = new sql.Connection(config);
        dbConn.connect().then(function() {

            let request = new sql.Request(dbConn);
            request.query(qry).then(function(dataset) {
                dbConn.close();
                res(null, dataset);

            }).catch(function(err) {
                dbConn.close();
                res('Failed to execute query - '+err);
            });
        }).catch(function(err) {
            res('Failed to connect to the SQL DB'+err);
        });
    }
};

module.exports = { sqlpool: sqlpool };
