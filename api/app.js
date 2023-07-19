require('dotenv').config();
const express = require('express');
const app = express();
const cors = require("cors")
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const path = require('path');
const cookieParser = require('cookie-parser');
const request = require('request')
const mysql = require('mysql');

const con = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
})


const bcrypt = require('bcrypt');
const saltRounds = 10;

app.use(express.json());
app.use(cors())
app.use(cookieParser())

app.use(express.static('./dashboard/login'));
app.use(express.static('./dashboard/board'));

app.disable('x-powered-by');

function authToken(req, res, next) {
    // const authToken = req.headers['authorization'];
    // const token = authToken && authToken.split(' ')[1];
    const token = req.cookies['access_token'];
    if (token == null) {
        res.status(401).json({
            status: "error",
        })
    } else {
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) {
                res.status(403).json({
                    status: "error",
                })
            } else {
                req.user = user;
                next();
            }
        })
    }

}

function validateClient(req, res, next) {
    const schema = Joi.object({
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        company: Joi.string(),
        phone: Joi.number().required(),
        city: Joi.string().required(),
        state: Joi.string().required(),
        address: Joi.string().required(),
        budget: Joi.number().required(),
        term: Joi.string().required(),
        message: Joi.string(),
        captcha: Joi.string().required()
    })

    const validateInput = (input) => schema.validate(input);

    const { error } = validateInput(req.body);
    if (error) {
        res.status(400).json({
            status: error.details[0].message,
        })
    } else {
        next();
    }
}


//TODO Uncomment this

// app.post('/newUser', async (req, res) => {
//     bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
//         if (err) {
//             console.log(err)
//         } else {
//             const newUser = new UserModel({
//                 username: req.body.username,
//                 password: hash
//             })

//             newUser.save().then(() => {
//                 res.status(200).json({
//                     status: "success",
//                 })

//             }).catch((err) => {
//                 console.log(err)
//                 res.status(500).json({
//                     status: "error",
//                 })

//             })
//         }
//     })
// })

app.get('/login', async (req, res) => {
    res.sendFile(path.resolve(__dirname, '../dashboard/login/index.html'))
})


app.get('/dashboard', authToken, (req, res) => {
    res.sendFile(path.resolve(__dirname, '../dashboard/board/index.html'))
})


app.post('/logout', (req, res) => {
    res.clearCookie('access_token', { maxAge: 3600000, httpOnly: true })
    res.status(200).json({
        path: '/login/'
    })
})



con.connect(function (err) {
    if (err) throw err;
    console.log("Connected!");

    app.post("/changePass", authToken, async (req, res) => {
        const hashed = await bcrypt.hash(req.body.newPassword, saltRounds);
        con.query("UPDATE users SET password = ? WHERE username = ?", [hashed, req.user.username], (err, result) => {
            if (err) {
                res.status(500).json({
                    status: "error",
                })
            } else {
                res.status(200).json({
                    status: "success",
                })
            }
        })
    })

    app.post('/login', async (req, res) => {
        con.query("SELECT * FROM users WHERE username = ?", [req.body.username], (err, result) => {
            if (result.length > 0) {
                bcrypt.compare(req.body.password, result[0].password, (err, result) => {
                    if (err) {
                        res.status(500).json({
                            status: "error1",
                        })
                    } else {
                        const username = req.body.username
                        const resUser = { name: username }
                        const accessToken = jwt.sign(resUser, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30m' })
                        res.cookie('access_token', accessToken, { maxAge: 3600000, httpOnly: true })
                        res.status(200).json({
                            path: '/dashboard/'
                        })
                    }
                })
            } else {
                res.status(500).json({
                    status: "error",
                })
            }
        });
    })

    app.get('/getAllClients', authToken, async (req, res) => {
        con.query("SELECT * FROM clients", (err, result) => {
            if (err) {
                res.status(500).json({
                    status: "error",
                })
            } else {
                res.status(200).json({
                    status: "success",
                    data: result
                })
            }
        })
    })

    app.delete('/deleteClient/:clientName', authToken, async (req, res) => {
        let clientName = req.params.clientName
        con.query("DELETE FROM clients WHERE name = ?", [clientName], (err, result) => {
            if (err) {
                res.status(500).json({
                    status: "error",
                })
            } else {
                res.status(200).json({
                    status: "success",
                })
            }
        })
    })

    app.delete('/clearDatabase', authToken, async (req, res) => {
        con.query("DELETE FROM clients", (err, result) => {
            if (err) {
                res.status(500).json({
                    status: "error",
                })
            } else {
                res.status(200).json({
                    status: "success",
                })
            }
        })
    })


    app.post("/newClient", validateClient, async (req, response) => {
        const secretKey = process.env.RECAPTCHA_SECRET

        const verifyUrl = `https://google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${req.body.captcha}&remoteip=${req.connection.remoteAddress}`

        let captchaPassed = false

        request(verifyUrl, (err, res, body) => {
            console.log(body);
            if (body.success == false) {
                return response.status(401).json({
                    msg: 'Failed'
                })
            } else {
                try {
                    con.query("INSERT INTO clients (name, email, phone, city, state, address, budget, term, message) VALUES (?,?,?,?,?,?,?,?,?)", [req.body.name, req.body.email, req.body.phone, req.body.city, req.body.state, req.body.address, req.body.budget, req.body.term, req.body.message], (err, result) => {
                        if (err) {
                            response.status(500).json({
                                status: "error",
                            })
                        } else {
                            response.status(200).json({
                                status: "success",
                            })
                        }
                    })
                } catch (err) {
                    return response.status(500).json({
                        status: "error",
                    })
                }
            }


        })


    })
});



module.exports = app;
