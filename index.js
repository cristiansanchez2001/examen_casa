const express = require('express')
const https = require('https')
//const Note = require('./models/Note')
const fs = require('fs')
const app = express()
const cookieSession = require('cookie-session')
const md = require('marked')
const CryptoJS = require('crypto-js');

const multer = require('multer')
const PORT = process.env.PORT || 3000
const db = require("./database.js")
const cookieParser = require('cookie-parser');
var bodyParser = require("body-parser");
const auth = require("./auth.js")
const cors = require('cors');
const authTokens = {};
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');

//app.use(express.urlencoded({extended: true}))


app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors())





//ruta para la lista de notas del usuario
app.get('/anotation/:user', auth.authenticateJWT, auth.leernota, (req, res) => {
    var sql = "SELECT note FROM notes WHERE user = ?";
    db.all(sql, [req.params.user], function (err, rows) {
        if (err){
            console.log(err)
            res.status(400).send("Error accediendo a las notas")
        }
        const notes = [];
        rows.forEach((row) => {notes.push(auth.decryptnota(row['note']))})
        res.status(200).send(notes)
    });
})


//ruta para crear una nota
app.post('/crear', auth.authenticateJWT, async (req, res, next)  => {
    const { anotation } = req.body;
    var sql = "INSERT INTO notes (user, note) VALUES (?,?)";
    db.run(sql, [req.user.id, (auth.encryptnota(anotation))], function (err) {
        if (err){
            console.log(err)
            res.status(400).send("Error guardando la nota")
        }
        res.status(200).send('Nota guardada.')
    });
});


//ruta para mostrar una nota
app.get('/nota/:user', auth.authenticateJWT, auth.leernota, (req, res) => {
    var sql = "SELECT note FROM notes WHERE user = ?";
    db.all(sql, [req.params.user], function (err, rows) {
        if (err){
            console.log(err)
            res.status(400).send("Error obteniendo las notas")
        }
        const notes = [];
        rows.forEach((row) => {notes.push(auth.decryptnota(row['note']))})
        res.status(200).send(notes)
    });
})




//ruta para eliminar una nota
app.delete("/nota/:id", auth.authenticateJWT, (req, res, next) => {  //Se le pasa el id de la nota a eliminar
    db.run(`DELETE FROM notes WHERE id = ?`,
        [req.params.id], function (err, result) {
            if (err){
                res.status(400).json({"error": res.message})
                return;
            }
            res.status(200).json({
                message: "success",
                deleted: this.changes === 1
            })
        }
    )
})
//ruta para registrarse
app.get('/register', (req, res) => {
    res.sendFile(__dirname + '/register.html');
})

//ruta para enviar el registro
app.post('/register', async (req, res, next) => {


const { username, email, password, adminCheck } = req.body;
const hashedPassword = auth.getHashedPassword(password);

var sql ='INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)'
var params =[username, email, hashedPassword, adminCheck === 'on']
db.run(sql, params, function (err) {
    if (err){ 
        console.log(err)
        res.status(400).send("Error al registrar, ya existe user")
        return;
    }
    res.status(200).send("Usuario registrado correctamente")
    return;
});
});



//ruta para enviar el login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    var sql = "SELECT * FROM users WHERE email = ?";
    db.all(sql, [email], (err, rows) => {
        if (err) {
            res.status(400).send("Error while login.")
        } else {
            const user = rows[0]
            if(user){
                if (auth.passvalida(password, user['password'])) {
                    const authToken = auth.generateAuthToken(user);
                    authTokens[authToken] = email;
                    res.cookie('AuthToken', authToken);
                    res.status(200).send("Ha iniciado sesion " + email)
                    return;
                } else {
                    res.status(403).send("Contraseña incorrecta")

                }
            } else {
                res.status(404).send("El usuario no existe")
            }
        }
    });
});
//ruta para hacer logout
app.get('/logout', (req, res) => {  
    if (req.user) {
        res.clearCookie('AuthToken'); 
        req.user = null
        res.redirect('/login')
    }
});


https.createServer({
    key: fs.readFileSync('code.key'),
    cert: fs.readFileSync('code.crt')
}, app).listen(PORT, () => {
    console.log("Servidor en https://localhost:" + PORT)
})