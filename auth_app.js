'use strict';

const async = require('async');
const conn = require('mssql-db');
const redis = require('redis');
const uuid = require('uuid/v4');
const saltedMd5 = require('salted-md5');

/* NOTE: This script requires the following variables are set as system variables with the correct values
    MSSQL_HOST, MSSQL_USER, MSSQL_PASSWORD, MSSQL_DB, MSSQL_PORT
    REDIS_HOST, REDIS_PORT, REDIS_DB

export MSSQL_HOST="security16.c4"
export MSSQL_USER="sa"
export MSSQL_PASSWORD="Empty$paces"
export MSSQL_DB="Security_16"
export MSSQL_PORT="1433"

export REDIS_HOST="redis.c4"
export REDIS_PORT="6379"
export REDIS_DB="1"

export MSSQL_HOST="db1-beta.control4.com"
export MSSQL_USER="sa"
export MSSQL_PASSWORD="Empty$paces"
export MSSQL_DB="Security_16"
export MSSQL_PORT="1433"

export REDIS_HOST="redis.c4"
export REDIS_PORT="6379"
export REDIS_DB="1"

 */

const sessionTTL = 1800; // seconds that token is valid for 60 * 30 => 30 mins

exports.handler = async (event, context, callback) => {
    // set variables
    console.log('event:', event);
    console.log('context', context);

    const body = JSON.parse(context);
    const username = body.username || '';
    const email = body.email || '';
    const passwd = body.password || '';
    const appKey = body.app_key || '';
    const appSecret = body.app_secret || '';
    let userContext;
    let accountId;
    let userId;
    let appId;
    let dealerId;
    let controllerCn;
    let perms = {};

    let retData = {
        principalId: "API gateway authorization",
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
            } else if (!apiKey) {
                cb('Missing required API Key field. ');
            } else if (!apiSecret) {
                cb('Missing required API Secret field. ');
            } else {
                cb(null);
            }
        },
        function(cb) {
            // validate the user credentials
            let qry = `SELECT u.PasswordSalt, u.PasswordHash, u.Id, u.AccountId, u.IsActive, u.Enabled, d.Id AS DealerId, d.Active AS DealerActive, 
                    a.TypeId, a.CertificateCommonName, a.Enabled AS AccountEnabled   
                FROM [User] u LEFT JOIN Dealer d ON (u.AccountId=d.AccountId) LEFT JOIN Account a ON (u.AccountId=a.Id) WHERE `+(username ? `Username='${username}'` : `Email='${email}'`);
            conn.sqlpool.query(qry, function(err, result) {
                if (err) { return cb('Failed to query user record - '+err); }
                if (result.length < 1) { return cb('No matching user record found'); }
                if (result[0].IsActive === false || result[0].Enabled === false) { return cb('The user account is either Inactive or disabled'); }

                // verify the password
                const passHash = saltedMd5(passwd, result[0].PasswordSalt);
                if (passHash !== result[0].PasswordHash) {
                    return cb('Invalid password for user account');
                }
                accountId = result[0].AccountId;
                userId = result[0].Id;
                if (result[0].TypeId === 1) {
                    userContext = 'consumer';
                    if (result[0].CertificateCommonName) {
                        controllerCn = result[0].CertificateCommonName;
                    }

                } else if (result[0].TypeId === 2) {
                    if (!result[0].DealerId || !result[0].DealerActive) { return cb('Missing or inactive Dealer account'); }
                    dealerId = result[0].DealerId;
                    userContext = 'dealer';

                } else if (result[0].TypeId === 4) {
                    userContext = 'distributor';

                } else {
                    userContext = 'application';
                }

                cb(null);
            });
        },
        function(cb) {
            // Verify the application credentials
            let qry = `SELECT id AS application_id, name AS application_name, app_secret FROM application WHERE app_key='${appKey}'`;
            conn.sqlpool.query(qry, function(err, result) {
                if (err) { return cb('Failed to query application records - '+err); }
                if (result.length < 1) { return cb('No matching application record matching credentials'); }
                if (result[0].app_secret !== appSecret) { return cb('Invalid password for application'); }
                appId = result[0].application_id;
                // override context to be application
                userContext = 'application';

                cb(null);
            });
        },
        function(cb) {
            // retrieve default services
            let qry = `SELECT s.service_name, s.service_subdomain, sd.service_write 
                FROM service_default sd LEFT JOIN service s ON (sd.service_id=s.service_id) 
                WHERE sd.service_context='application'`;
            conn.sqlpool.query(qry, function(err, permSet) {
                if (err) { return cb('Failed to retrieve default services - '+err); }
                if (permSet.length > 0) {
                    async.each(permSet, function(row, cback) {
                        if (perms[row.service_name] === undefined) {
                            perms[row.service_name] = {
                                policies: [],
                                service_subdomain: row.service_subdomain,
                                service_write: row.service_write
                            };
                        } else if (perms[row.service_name].service_write < row.service_write) {
                            perms[row.service_name].service_write = row.service_write;
                        }
                        cback();

                    }, function(err) {
                        if (err) { return cb(err); }
                        cb(null);
                    });
                }
            });
        },
        function(cb) {
            // lookup application permissions and policies
            let qry = `(SELECT s.service_name, s.service_subdomain, sp.policy_name, sp.policy_scope, sp.site_required, sp.os_requirement, sp.primary_only, sp.policy_rule, ap.include_write AS policy_write 
                FROM application a LEFT JOIN application_permission ap ON (a.application_id=ap.application_id)
                    LEFT JOIN service s ON (ap.service_id=s.service_id) 
                    LEFT JOIN service_policy sp ON (ap.policy_id=sp.policy_id) 
                WHERE a.application_id=${appId})  
                UNION 
                (SELECT s.service_name, s.service_subdomain, sp.policy_name, sp.policy_scope, sp.site_required, sp.os_requirement, sp.primary_only, sp.policy_rule, pd.policy_write 
                FROM policy_default pd LEFT JOIN service_policy sp ON (pd.policy_id=sp.policy_id) 
                    LEFT JOIN service s ON (sp.service_id=s.service_id) 
                WHERE pd.policy_context='application') 
                ORDER BY service_name ASC, policy_name ASC`;
            conn.sqlpool.query(qry, function(err, permSet) {
                if (err) { return cb('Failed to retrieve permissions and policies - '+err); }
                if (permSet.length > 0) {
                    async.each(permSet, function(row, cback) {
                        // make sure service is defined
                        if (perms[row.service_name] === undefined) {
                            perms[row.service_name] = {
                                policies: [],
                                service_subdomain: row.service_subdomain,
                                service_write: row.service_write
                            };
                        }
                        // add policy
                        if (perms[row.service_name].policies[row.policy_name] === undefined) {
                            perms[row.service_name].policies[row.policy_name] = {
                                scope: row.policy_scope,
                                write: row.policy_write,
                                site_required: row.site_required,
                                os_requirement: row.os_requirement,
                                primary_only: row.primary_only,
                                rules: row.policy_rule

                            };
                        } else {
                            // update / append values to existing record
                            if (perms[row.service_name].policies[row.policy_name].scope !== row.policy_scope && row.policy_scope) {
                                perms[row.service_name].policies[row.policy_name].scope += ', '+row.policy_scope;
                            }
                            if (perms[row.service_name].policies[row.policy_name].write < row.policy_write) {
                                perms[row.service_name].policies[row.policy_name].write += ', '+row.policy_write;
                            }
                            if (perms[row.service_name].policies[row.policy_name].site_required < row.site_required {
                                perms[row.service_name].policies[row.policy_name].site_required = row.site_required;
                            }
                            if (perms[row.service_name].policies[row.policy_name].os_requirement < row.os_requirement) {
                                perms[row.service_name].policies[row.policy_name].os_requirement = row.os_requirement;
                            }
                            if (perms[row.service_name].policies[row.policy_name].primary_only < row.primary_only) {
                                perms[row.service_name].policies[row.policy_name].scope = row.primary_only;
                            }
                            if (perms[row.service_name].policies[row.policy_name].rules !== row.policy_rule && row.policy_rule !== '' && row.policy_rule !== null) {
                                perms[row.service_name].policies[row.policy_name].rules += ', '+row.policy_rule;
                            }
                        }
                        cback();

                    }, function(err) {
                        if (err) { return cb(err); }
                        cb(null);
                    });
                }
            });
        },
        function(cb) {
            // set the user values and permissions to store in cache
            let payload = {
                'X-User': {
                    user_id: userId,
                    account_id: accountId,
                    app_id: appId,
                    context: userContext
                },
                'X-Permissions': {
                    services: perms
                }
            };
            if (dealerId) { payload["X-User"].dealer_id = dealerId; }
            if (controllerCn) { payload["X-User"].controller_cn: controllerCn; }

            cb(null, payload);
        },
        function(payload, cb) {
            // generate UUID token and add token to Redis
            let options = {
                host: process.env.REDIS_HOST,
                port: process.env.REDIS_PORT || 6397,
                db: process.env.REDIS_DB || 1
            };
            const client = redis.createClient(options);
            let avail = false;
            let token = uuid();

            async.whilst(
                function test(cb2) { cb2(null, avail); },
                function iter(cback) {
                    client.get(token, function(err, result) {
                        if (result === '') {
                            avail = true;
                        }
                        cback(err, token);
                    });
                },
                function (err, token) {
                    if (err) { return cb('An error occurred - '+err); }
                    client.set([token, JSON.stringify(payload), 'EX', sessionTTL], function(err) {
                        if (err) { return cb('Failed to save token to session DB. '+err); }
                        client.quit();
                        retData.context.access_token = token;
                        cb(null);
                    });
                }
            );
        }

    ], function(err) {
        if (err) {
            return callback(err);
        }
        callback(retData);
    });
};
