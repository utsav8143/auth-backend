import * as nodeMailer from "nodemailer";
import config from "../config/config.js";

const transporter = nodeMailer.createTransport({
  service: "gmail",
  auth: {
    type: "OAuth2",
    user: config.GOOGLE_USER,
    clientId: config.GOOGLE_CLIENT_ID,
    clientSecret: config.GOOGLE_CLIENT_SECRET,
    refreshToken: config.GOOGLE_REFRESH_TOKEN,
  },
});

// Verify the connection configuration
transporter.verify((error, success)=>{
    if(error){
        console.log("Error connecting to email server",error)
    } else{
        console.log("Email server is ready to send messages")
    }
    })

    export const sendEmail=async (to, subject, text, html)=>{
        try{
            const info=await transporter.sendMail({
                from:`"Your Name"<${config.GOOGLE_USER}>`, //sender address
                to,
                subject,
                text,
                html,
            });

            console.log("Message sent: %s", info.messageId);
            console.log("Preview URL: %s", nodeMailer.getTestMessageUrl(info));
        } catch(err){
            console.log("Error sending email",err);
        }
    }