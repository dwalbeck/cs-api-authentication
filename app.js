'use strict';

const async = require('async');
const sql = require('mssql');
const mysql = require('mysql');
const uid = require('uuid/v4');

const myHost = 'mysql.c4';
const myUser = 'CertUser';
const myPass = 'D!ff3ren+';
const myDB = 'ca_db';


exports.handler = async (event, context, callback) => {
    // set variables
    const appKey = event.body-json.authenticateController.applicationKey || '';
    const cn = event.body-json.authenticateController.controllerCommonName || '';
    const authVer = event.body-json.authenticateController.oauthVersion || '';
    const cert = event.params.header.X509-Certificate || '';

    let conn = mysql.createConnection({
        host: myHost,
        user: myUser,
        password: myPass,
        database: myDB
    });
    conn.connect(function(err) {
        if (err) {
            console.error('Failed to connect to Certificate DB. '+err);
            return callback('Failed to connect to Certificate DB. '+err);
        }
    });


    async.waterfall([
        function(cb) {
            // validate req data
            if (!appKey) {
                cb('Missing required applicationKey field. ');
            } else if (!cn) {
                cb('Missing required controllerCommonName field. ');
            } else if (!authVer) {
                cb('Missing required oauthVersion field. ');
            } else if (!cert) {
                cb('Missing required SSL certificate pem. ');
            } else {
                cb(null);
            }
        },
        function(cb) {
            // verify entry in certificate DB
            let sql = `SELECT seq, valid FROM certificates WHERE cert='${cert}' AND cn='${cn}'`;
            conn.query('SELECT seq, valid FROM certificates WHERE cert = ? AND cn = ?', [cert, cn], function(err, res, data) {
                if (err) { return cb('An error occurred retrieving certificate records. '+err); }
                if (res[0].valid === 0) {
                    return cb('Certificate provide is not valid or active. ');
                }
                cb(null);
            });
        },
        function(cb) {
            // call the certificate service to verify cert is active and chain checks out

            cb(null);
        },
        function(cb) {
            // lookup application by appKey and get permissions


        },
        function(cb) {
            // generate UUID token and add token to DB/cache

            cb(null);
        }

    ], function(err) {
        if (err) {
            return callback(err);
        }
    });
};
