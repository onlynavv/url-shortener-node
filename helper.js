import { client } from "./index.js";
import bcrypt from "bcrypt"

async function getByUserName(username){
    return await client.db("password").collection("users").findOne({username:username})
}

async function genPassword(password){
    const NO_OF_ROUNDS = 10
    const salt = await bcrypt.genSalt(NO_OF_ROUNDS)
    console.log(salt)
    const hashedPassword = await bcrypt.hash(password, salt)
    console.log(hashedPassword)
    return hashedPassword
}

async function createUser(data) {
    return await client.db("password").collection("users").insertOne(data);
}

export {getByUserName,genPassword,createUser}