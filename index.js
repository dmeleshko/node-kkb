var Crypto = require('crypto');
var fs = require('fs');
var xml2js = require('xml2js');
var Buffer = require('buffer').Buffer;

// Функции для работы с цифровой подписью

function sign(data, privateKeyFile, privateKeyPass, cb) {
    fs.readFile(privateKeyFile, (err, pkData) => {
        if(err) return cb(err, "Error reading private key file");
        var pk = {
            key: pkData.toString('ascii'),
            passphrase: privateKeyPass
        };

        var sign = Crypto.createSign('RSA-SHA1');
        sign.update(data);

        // После подписания требуется инвертировать строку

        var revsign = sign.sign(pk);
        revsign.reverse();
        
        // Затем кодируем в base64

        var revstr = revsign.toString('base64');

        try {
            return cb(false, revstr);
        } catch (e) {
            return cb(true, e.message);
        }
    })
}

function verify (data, sign, publicKeyFile, cb) {
    fs.readFile(publicKeyFile, (err, pubData) => {
        if(err) return cb(err, "Error reading public key file");
        var pub = pubData.toString('ascii');
        var verify = Crypto.createVerify('RSA-SHA1');
        verify.update(data);
        return cb(false, verify.verify(pub, sign, 'base64'));
    });
}

// Функции для работы с xml

function merchantObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency) {
    return {
        '$': {
            cert_id: cert_id,
            name: merchant_name
        },
        order: [{
            '$': {
                order_id: order_id,
                amount: order_amount,
                currency: order_currency || 398
            },
            department: [{
                '$': {
                    merchant_id: merchant_id,
                    amount: order_amount
                }
            }]
        }]
    };
}

function merchantXml(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency) {
    var merObj = merchantObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency);
    var builder = new xml2js.Builder({rootName: 'merchant', headless: true, renderOpts: {'pretty': false}});
    return builder.buildObject(merObj);
}

function documentObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency, signBase64) {
    return {
        merchant: merchantObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency),
        merchant_sign: {
            '$': {
                type: 'RSA'
            },
            '_': signBase64
        }
    };
}

function documentXml(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency, signBase64) {
    var docObj = documentObj(cert_id, merchant_id, merchant_name, order_id, order_amount, order_currency, signBase64);
    var builder = new xml2js.Builder({rootName: 'document', headless: true, renderOpts: {'pretty': false}});
    return builder.buildObject(docObj);
}

function getSignedOrderXml(config, order_id, order_amount, order_currency, cb) {
    try {
        var merXml = merchantXml(config.cert_id, config.merchant_id, config.merchant_name, order_id, order_amount, order_currency);
        sign(merXml, config.privateKeyFile, config.privateKeyPass, (err, data) => {
            if(err) return cb(err, data);
            return cb(false, documentXml(config.cert_id, config.merchant_id, config.merchant_name, order_id, order_amount, order_currency, data));
        });
    } catch (e) {
        return cb(true, e.message);
    }
}

function getSignedOrderBase64(config, order_id, order_amount, order_currency, cb) {
    getSignedOrderXml(config, order_id, order_amount, order_currency, (err, data) => {
        if(err) return cb(err, data);
        var buf = new Buffer(data);
        return cb(false, buf.toString('base64'));
    });
}

// Создание xml товара


function itemXml(item_number, item_name, item_quantity, item_amount) {
    var itObj = itemObj(item_number, item_name, item_quantity, item_amount);
    var builder = new xml2js.Builder({rootName: 'document', headless: true, renderOpts: {'pretty': false}});
    return builder.buildObject(itObj);
}

function itemObj(item_number, item_name, item_quantity, item_amount) {
    return {
        item: [{
            '$': {
                number: item_number,
                name: item_name,
                quantity: item_quantity,
                amount: item_amount
            }
        }]
    }
}

function itemObjBase64(item_number, item_name, item_quantity, item_amount) {
    var itex = itemXml(item_number, item_name, item_quantity, item_amount);
    var itexbase = new Buffer(itex);
    var itexstring = itexbase.toString('base64');
    return itexstring;
}


function splitBankAnswer(xmlString, cb) {
    var parser = new xml2js.Parser();
    parser.parseString(xmlString, (err, data) => {
        if(err) return cb(err, data);
        var builder = new xml2js.Builder({rootName: 'bank', headless: true, renderOpts: {'pretty': false}});
        var xmlBank = builder.buildObject(data['document']['bank'][0]);
        var res = {
            xml: xmlBank,
            sign: data['document']['bank_sign'][0]['_']
        }
        return cb(false, res);
    });
}

function parseBankAnswer(config, xmlString, cb) {
    splitBankAnswer(xmlString, (err, data) => {
        if(err) return cb(err, data);
        verify(data.xml, data.sign, config.publicKeyFile, (err, result) => {
            if(err) return cb(err, result);
            var parser = new xml2js.Parser();
            parser.parseString(data.xml, (err, answer) => {
                if(err) return cb(err, answer);
                var res = {
                    customer: {
                        name: answer.bank.customer[0]['$'].name,
                        mail: answer.bank.customer[0]['$'].mail,
                        phone: answer.bank.customer[0]['$'].phone
                    },
                    merchant: {
                        name: answer.bank.customer[0].merchant[0]['$'].name
                    },
                    order: {
                        id: answer.bank.customer[0].merchant[0].order[0]['$'].order_id,
                        amount: answer.bank.customer[0].merchant[0].order[0]['$'].amount,
                        currency: answer.bank.customer[0].merchant[0].order[0]['$'].currency,
                    },
                    department: {
                        amount: answer.bank.customer[0].merchant[0].order[0].department[0]['$'].amount
                    },
                    payment: {
                        timestamp: answer.bank.results[0]['$'].timestamp,
                        merchant_id: answer.bank.results[0].payment[0]['$'].merchant_id,
                        amount: answer.bank.results[0].payment[0]['$'].amount,
                        reference: answer.bank.results[0].payment[0]['$'].reference,
                        approval_code: answer.bank.results[0].payment[0]['$'].approval_code,
                        response_code: answer.bank.results[0].payment[0]['$'].response_code
                    },
                    check_result: result?'SIGN_GOOD':'SIGN_BAD'
                }
                return cb(false, res);
            });
        });
    });
}

exports.getSignedOrderBase64 = getSignedOrderBase64;
exports.parseBankAnswer = parseBankAnswer;
