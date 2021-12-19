import express from "express"
import { MongoClient } from "mongodb";
import dotenv from "dotenv"
import cors from "cors"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import { genPassword, createUser,getByUserName,getByUserId,updatePassword,createUrl,getAllUrls, findUrl,getAllUrlsDay,getAllUrlsMonth,changeUserStatus} from "./helper.js"
import {nanoid} from "nanoid"
import nodemailer from "nodemailer"
import sendgridTransport from "nodemailer-sendgrid-transport"
import { authAndVerifyUser } from "./auth.js";

dotenv.config()

const app = express()

const PORT = process.env.PORT;

app.use(cors())

app.use(express.json())

const MONGO_URL = process.env.MONGO_URL

async function createConnection(){
    const client = new MongoClient(MONGO_URL)
    await client.connect()
    console.log("mongodb connected")
    return client
}

export const client = await createConnection()

const transporter = nodemailer.createTransport(sendgridTransport({
    auth:{
        api_key:process.env.TRANSPORT_KEY
    }
}))

app.get("/", (request, response)=>{
    response.send("hai from reset password")
})

// user registration

app.post("/register", async(request, response)=>{
    const {username, password, email, isActive,firstname,lastname} = request.body
    const userFromDB = await getByUserName(username)

    if(userFromDB){
        response.status(400).send({msg:"username already exists"})
        return
    }

    if(password.length < 8){
        response.status(400).send({msg: "password must be longer"})
        return
    }

    if(!/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(password)){
		response.status(400).send({msg: "pattern does not match"})
		return
	}

    const hashedPassword = await genPassword(password)
    const token = jwt.sign({username:username, email:email}, process.env.SECRET_KEY)
    const result = await createUser({username,firstname,lastname, password:hashedPassword, email, isActive, token})
    const link = `https://url-shortener-api-task.herokuapp.com/verifyAuth/${username}/${token}`

    transporter.sendMail({
        to:email,
        from: process.env.FROM_MAIL,
        subject:"Account Verification",
        html:`
            <h4>Email Verification, Activate your account</h4>
            <h4>click this <a href=${link}>link</a> to verify your account</h4>

        `
    })
    response.send({result, msg:"email has been sent to your email address, please verify your account"})
})

// verify the account for account activation

app.get("/verifyAuth/:username/:token", async(request, response)=>{
    const {username, token} = request.params
    const userFromDB = await getByUserName(username)

    if(!userFromDB){
        response.send({msg:"invalid credentials"})
        return
    }

    try{
        const result = jwt.verify(token, process.env.SECRET_KEY)
        // response.send(result)
        const changeStatus = await changeUserStatus(username)
        response.redirect(`https://url-shortener-app-task.netlify.app/login`)
    }catch(error){
        response.send(error.message)
    }
})

// login

app.post("/login", async(request, response)=>{
    const {username, password} = request.body
    const userFromDB = await getByUserName(username)

    if(!userFromDB){
        response.status(401).send({msg:"incorrect credentials"})
        return
    }

    const storedPassword = userFromDB.password

    const isPasswordMatch = await bcrypt.compare(password, storedPassword)

    if(isPasswordMatch){
        const token = jwt.sign({id:userFromDB._id, username:username, isActive:userFromDB.isActive}, process.env.SECRET_KEY)
        response.send({msg:"successfull login",token:token, username:username, isActive:userFromDB.isActive})
    }else{
        response.status(401).send({msg: "incorrect credentials"})
    }
})

// forgot password

app.post("/forgot-password", async(request, response)=>{
    const {username} = request.body
    const userFromDB = await getByUserName(username)

    if(!userFromDB){
        response.status(401).send({msg:"user does not exist"})
        return
    }

    // token
    const secret = process.env.SECRET_KEY + userFromDB.password
    const token = jwt.sign({email:userFromDB.email, id:userFromDB._id, username:userFromDB.username},secret,{expiresIn: "15m"})
    

    const link = `https://url-shortener-api-task.herokuapp.com/${userFromDB._id}/${token}`
    
    transporter.sendMail({
        to:userFromDB.email,
        from: process.env.FROM_MAIL,
        subject:"password reset",
        html:`
            <h4>You have requested for the password reset</h4>
            <h4>click this <a href=${link}>link</a> to reset password</h4>

        `
    })
    response.send({msg:"password reset link has been sent to your email address"})
})

// verify the token
app.get("/reset-password/:id/:token", async(request, response, next)=>{
    const {id, token} = request.params
    const userFromDB = await getByUserId(id)

    if(!userFromDB){
        response.send({msg:"invalid credentials"})
        return
    }

    const secret = process.env.SECRET_KEY + userFromDB.password
    try{
        const result = jwt.verify(token, secret)
        // response.send(result)
        response.redirect(`https://url-shortener-app-task.netlify.app/reset/${userFromDB._id}/${token}`)
    }catch(error){
        response.send(error.message)
    }
})

// reset password
app.put("/reset-password/:id/:token", async(request, response, next)=>{
    const {id, token} = request.params
    const {password} = request.body
    const userFromDB = await getByUserId(id)
    
    if(!userFromDB){
        response.send({msg:"invalid credentials"})
        return
    }

    const secret = process.env.SECRET_KEY + userFromDB.password
    
    try{
        const result = jwt.verify(token, secret)
        if(password.length < 8){
            response.status(400).send({msg: "password must be longer"})
            return
        }

        if(!/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(password)){
            response.status(400).send({msg: "pattern does not match"})
            return
        }

        const hashedPassword = await genPassword(password)
        const data  = await updatePassword(id,hashedPassword)
        response.send({msg:"password changed successfully, wait for 5 secs the page to redirect..."})
    }catch(error){
        response.send(error.message)
    }

})

// get all the urls
app.get("/urlshortener/urls/:user", async (request, response)=>{
    const {user} = request.params
    const result = await getAllUrls(user)
    response.send(result)
})

// long url
app.post("/urlshortener/create", authAndVerifyUser,async (request, response)=>{
    
    const {inputurl, user} = request.body
    
    const shortUrl = nanoid(6)
    const timestamp = Date.now()
    const dataInfo = new Date(timestamp)
    const date = dataInfo.getDate()
    const month = dataInfo.getMonth()
    const year = dataInfo.getFullYear()
    const dateTime = date + "-" + month + "-" + year
    const monthData = month + "-" + year
    const userFromDB = await getByUserName(user)

    if(!userFromDB){
        response.status(401).send({msg:"incorrect credentials"})
        return
    }
    const data = {inputurl, shortUrl, username:user,createdAt:dateTime, createdMonth:monthData}
    
    const result = await createUrl(data)
    response.send(result)
})

// access short url
app.get("/urlshortener/:id", async(request,response)=>{
    const {id} = request.params
    
    const urlFromDB = await findUrl(id)
    

    if(!urlFromDB){
        response.status(404).send({msg:"invalid url entered"})
    }

    response.redirect(urlFromDB.inputurl)
})

// urls created per day
app.get("/urldashboard/:user", async(request, response)=>{
    const {user} = request.params
    const timestamp = Date.now()
    const dataInfo = new Date(timestamp)
    const date = dataInfo.getDate()
    const month = dataInfo.getMonth()
    const year = dataInfo.getFullYear()
    const dateTime = date + "-" + month + "-" + year
    const data = {user, dateTime}
    
    const result = await getAllUrlsDay(data)
    
    response.send({count:result})
})

// urls created per month
app.get("/urldashboard/month/:user", async(request, response)=>{
    const {user} = request.params
    const timestamp = Date.now()
    const dataInfo = new Date(timestamp)
    const date = dataInfo.getDate()
    const month = dataInfo.getMonth()
    const year = dataInfo.getFullYear()
    const monthData = month + "-" + year
    const data = {user, monthData}
    const result = await getAllUrlsMonth(data)
    response.send({count:result})
})

app.listen(PORT, ()=>{
    console.log("app started at ", PORT)
})