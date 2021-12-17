import express from "express"
import { MongoClient } from "mongodb";
import dotenv from "dotenv"
import cors from "cors"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import { genPassword, createUser,getByUserName } from "./helper.js"

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

app.get("/", (request, response)=>{
    response.send("hai from reset password")
})

app.post("/register", async(request, response)=>{
    const {username, password, email} = request.body
    const userFromDB = await getByUserName(username)
    console.log(userFromDB)

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
    const result = await createUser({username, password:hashedPassword, email})
    response.send(result)
})

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
        const token = jwt.sign({id:userFromDB._id, username:username}, process.env.SECRET_KEY)
        response.send({msg:"successfull login",token:token, username:username})
    }else{
        response.status(401).send({msg: "incorrect credentials"})
    }
})

app.listen(PORT, ()=>{
    console.log("app started at ", PORT)
})