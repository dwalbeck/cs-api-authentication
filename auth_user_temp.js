'use strict';

const async = require('async');
const sql = require('mssql');
const redis = require('redis');
const uuid = require('uuid/v4');
const saltedMd5 = require('salted-md5');

const sqlHost = 'mysql.c4';
const sqlUser = 'CertUser';
const sqlPass = 'D!ff3ren+';
const sqlDB = 'ca_db';

const redisHost = 'redis.c4';
const redisPort = '6379';
const redisDB = 3;

const sessionTTL = 1800; // seconds that token is valid for 60 * 30 => 30 mins

exports.handler = async (event, context, callback) => {
    // set variables
    const username = event.body-json.username || '';
    const email = event.body-json.email || '';
    const passwd = event.body-json.password || '';
    const config = {
        user: sqlUser,
        password: sqlPass,
        server: sqlHost,
        database: sqlDB,
        pool: {
            max: 10,
            min: 0,
            idleTimeoutMillis: 5000
        }
    };
    let retData = {
        principalId: "API gateway auth",
        policyDocument: {
            Version: "2012-10-17",
            Statement: [
                {
                    Action: "execute-api:Invoke",
                    Effect: "Deny",
                    Resource: "arn:aws:execute-api:{regionId}:{accountId}:{apiId}/{stage}/{httpVerb}/[{resource}/[{child-resources}]]"
                }
            ]
        },
        context: {},
        usageIdentifierKey: "{api-key}"
    };

    let qry = `SELECT Username, Email, PasswordSalt, PasswordHash, Id, AccountId FROM Security_16.dbo.[User] WHERE IsActive=1 AND [Enabled]=1`;
    if (username) { qry += ` AND Username='${username}'`; }
    if (email) { qry += ` AND Email='${email}'`; }

    sql.on('error', err => {
        // error handler
        callback('An error occurred connecting with the DB. '+err);
    });

    async.waterfall([
        function(cb) {
            // validate req data
            if (!username && !email) {
                cb('Missing required Username or Email. ');
            } else if (!passwd) {
                cb('Missing required Password field. ');
            } else {
                cb(null);
            }
        },
        function(cb) {
            // query for the User record from Security16
            sql.connect(config).then(pool => {
                return pool.request()
                    .query(qry)
            }).then(result => {
                if (result.recordset.length < 1) {
                    return cb('No matching account was found. ');
                }
                cb(null, result.recordset[0]);
            }).catch(err => {
                cb('Error while querying the DB - '+err);
            });
        },
        function(user, cb) {
            // Use salt to encrypt password and verify
            const passHash = saltedMd5(passwd, user.PasswordSalt);
            if (passHash !== user.PasswordHash) {
                return cb('Invalid password and/or login credentials. ');
            }
            cb(null, user);
        },
        function(user, cb) {
            // lookup user permissions and policies
            let payload = {
                'X-User': {
                    user_id: user.Id
                },
                'X-Permissions': {}
            };
            cb(null, payload);
        },
        function(payload, cb) {
            // generate UUID token and add token to Redis

            let options = {
                host: redisHost,
                port: redisPort,
                db: redisDB
            };
            const client = redis.createClient(options);
            let token = uuid();

            async.until(function(token, cb2) {
                client.get(token, function(err, result) {
                    if (result.length > 0) {
                        err = 'Found record';
                    }
                    cb2(err, token);
                });
            }, function(cb3) {
                token = uuid();
                cb3(null, token);
            }, client.set([token, payload, 'EX', sessionTTL], function(err) {
                if (err) { return cb('Failed to save token to session DB. '+err); }

                client.quit();
                retData.context.token = token;
                retData.context.user = payload.X-User;
                retData.context.permission = payload.X-Permissions;
                cb(null);
            });
        }

    ], function(err) {
        if (err) {
            return callback(err);
        }
        callback(retData);
    });
};
