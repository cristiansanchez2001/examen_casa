const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
const secret = 'firmacristiansanchez'
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const ENCODING = 'hex'

const getHashedPassword = (password) => {
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(password, salt);
}

const passvalida = (password, hash) => {
   return bcrypt.compareSync(password, hash);
}

const generateAuthToken = (user) => {
    return jwt.sign({
        name: user.name,
        email: user.email,
        id: user.id,
        role: user.role
    }, secret, {expiresIn: '2h'});
}

function authenticateJWT(req, res, next){
    const token = req.cookies['AuthToken']
    if (token) {
        jwt.verify(token, secret, (err, user) => { 
            if (err) { 
                return res.sendStatus(403); 
            }
            req.user = user;
            next();
        });
    } else { 
        res.status(403).send('Inicia sesion antes');
        }
};

function authorizeAdmin(req, res, next){ 
    if(req.user.role === '1') {
        next()
    } else {
        res.sendStatus(401); 
    }
};

const eliminarnota = (req, res, next) => {
    if(req.user.role || usereliminarnota(req.user, req.params.id)){
        next()
    } else {
        res.status(403).send('No puede eliminar esta nota');
    }
}



const leernota = (req, res, next) => {
    if(req.user.role || req.user.id == req.params.user){
        next()
    } else {
        res.status(403).send('No puede leer las notas de este usuario');
    }
}



const encryptnota = (text) => {
    const passphrase = '123';
    return CryptoJS.AES.encrypt(text, passphrase).toString();
  };



const decryptnota = (ciphertext) => {
    const passphrase = '123';
    const bytes = CryptoJS.AES.decrypt(ciphertext, passphrase);
    const originalText = bytes.toString(CryptoJS.enc.Utf8);
    return originalText;
  };




module.exports = { getHashedPassword, passvalida, eliminarnota, generateAuthToken, leernota, authenticateJWT, authorizeAdmin, encryptnota, decryptnota}