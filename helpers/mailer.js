const { error } = require("console")
const nodemailer = require("nodemailer")

const transporter = nodemailer.createTransport({
     
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth : {
        user: "630425b53abc30",
        pass: "e65d9c46459826"
    }
})


const sendMail = async(email, subject, content) => {
    try {
        mailOptions = {
            from : 'abdullah@gmail.com',
            to : email,
            subject : subject,
            html : content
        }

        transporter.sendMail(mailOptions, (error, info)=> {
            if(error) {
                console.log(error)
            }
            console.log('Mail has been sent', info.messageId)
        })
    } catch (error) {
        console.log(error.message)
    }
}

module.exports = {
    sendMail
}