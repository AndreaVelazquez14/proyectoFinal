const { User } = require('../models');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const ForgotPassword = {
    async sendMail(reg, res) {
        if (req.body.email == "") {
            res.status(400).send({
                message: 'El email es requerido'
            })
        }


        try {
            const user = await User.findOne({
                where: {
                    email: req.body.email
                }
            })

            if (!user) {
                return res.status(403).send({
                    message: 'No existe ese email'
                })
            }

            const token = jwt.sign({ id: user.id }, 'esternocleidomastoideo', { expiresIn: "1h" });
            user.update({
                tokenResetPassword: token
            });

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: '${process.env.EMAIL_ADDRESS}',
                    pass: '${process.env.EMAIL_PASSWORD}',
                }
            });

            const emailPort = process.env.EMAIL_PORT || 3000;

            const mailOptions = {
                from: 'bot.elbarquitodepapelfi@gmail.com',
                to: '$(user.email)',
                subject: "Enlace para recuperar su cuenta de La Aplicacion web",
                text: '$(emailPort)/resetpassword/$(user.id)/$(token)'
            };

            transporter.sendMail(mailoptions, (err, response) => {
                if (err) {
                    console.error('Ha ocurrido un error:', err);
                } else {
                    console.log('Respuesta:', response);
                    res.status(200).json('El email para la recuperacion ha sido enviado');
                }
            })

        } catch (error) {
            res.status(500).send({
                message: 'Ha ocurrido un error',
                error
            })
        }
    }
}

module.exports = ForgotPassword;

