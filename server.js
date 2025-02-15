const express=require("express")
const cors=require("cors")
const app=express()

const {open}=require("sqlite")
const sqlite3=require("sqlite3")

const path=require("path")
const dbPath=path.join(__dirname,"taskTracker.db")

const bcrypt=require("bcrypt")
const jwt=require("jsonwebtoken")
const { request } = require("http")

app.use(express.json())
app.use(cors())

let db;
const initServerAndDb= async ()=>{

  try{
      db=await open({
      filename:dbPath,
      driver:sqlite3.Database
    })

    app.listen(4000,()=>{
      console.log("The server is running at port 4000")
    })

  }catch(err){
    console.log(`Database Error ${err.message}`);
    process.exit(1)
  }
  

}

initServerAndDb()

const authenticateToken= async (request,response,next)=>{
  let jwtToken;

  const authHeader = request.headers["authorization"];

  if(authHeader!==undefined){
    jwtToken=authHeader.split(" ")[1]
  }

  if(jwtToken===undefined){
   return response.status(401).send("Invalid JWT Token")
  }

  jwt.verify(jwtToken,"MY_SECRET_TOKEN", async (err,payload)=>{

    if(err){
      return response.status(401).send("MY_SECRET_TOKEN")
    }
    
      request.email=payload.email;
      next();
    
  })

}

const getUserId = async (email) => {
  const userIdQuery = `SELECT id FROM users WHERE email = ?`;
  const user = await db.get(userIdQuery, [email]);
  return user ? user.id : null;
};



app.post('/signup/', async (request,response)=>{
  try {
    const { name, email, password } = request.body;

    // Check if the user already exists
    const selectUserQuery = `SELECT * FROM users WHERE email = ?`;
    const dbUser = await db.get(selectUserQuery, [email]);

    if (dbUser) {
      return response.status(400).send("User already exists");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    const createUserQuery = `
      INSERT INTO users (name, email, password) 
      VALUES (?, ?, ?)`;
    
    const dbResponse = await db.run(createUserQuery, [name, email, hashedPassword]);

    response.status(201).send(`Created new user with ID: ${dbResponse.lastID}`);
  } catch (error) {
    console.error(error);
    response.status(500).send("Internal Server Error");
  }
  

})



app.post('/login/', async (request,response)=>{
  const {email, password } = request.body;

  try{

     // Check if the user already exists
     const selectUserQuery = `SELECT * FROM users WHERE email = ?`;
     const dbUser = await db.get(selectUserQuery, [email]);

     if(dbUser===undefined){
      return response.status(400).send("Invalid User")
     }

     const isPasswordMatched = await bcrypt.compare(password, dbUser.password);

     if(isPasswordMatched){
      const payload={
        email
      }

      const jwtToken=jwt.sign(payload,"MY_SECRET_TOKEN")

      response.status(200).send({jwtToken})

     }else{
      response.status(401).send("Invalid Password")
      
     }

    


  }catch(error){
    response.status(500).send("Internal Server Error");
  }

})



app.get("/tasks/", authenticateToken, async (request,response)=>{
  const {email}=request;
  const userId=await getUserId(email);
  console.log(userId)

  const tasksQuey=`SELECT * FROM tasks WHERE user_id=?`;
  const tasks=await db.all(tasksQuey,[userId]);
  
  response.send(tasks);
})



app.post("/tasks/", authenticateToken, async (request,response)=>{

  const {email}=request;
  const {title,description,status,dueDate}=request.body

  const userId=await getUserId(email);

  const insertQuery=`INSERT INTO tasks 
   (title,description,status,due_date,user_id)
   VALUES (?,?,?,?,?)`;

  await db.run(insertQuery,[title,description,status,dueDate,userId]);
  response.status(201).send("Task Succesfully Added");

})

app.put("/tasks/:taskId", authenticateToken, async (request,response)=>{
  const {email}=request
  const {taskId}=request.params

  const {title,description,status,dueDate}=request.body

  const userId=await getUserId(email);

  const updates=[];
  const values=[];

  if (title) {
    updates.push("title = ?");
    values.push(title);
  }

  if (description) {
    updates.push("description = ?");
    values.push(description);
  }

  if (status) {
    updates.push("status = ?");
    values.push(status);
  }

  if (dueDate) {
    updates.push("due_date = ?");
    values.push(dueDate);
  }

  const updateQuery = `
  UPDATE tasks 
  SET ${updates.join(", ")}
  WHERE id = ? AND user_id = ?
  `;

  values.push(taskId,userId)

  await db.run(updateQuery, values);

  response.status(200).send("Task updated successfully")

})



app.delete("/tasks/:taskId", authenticateToken, async(request,response)=>{
  const {email}=request
  const {taskId}=request.params

  const userId=await getUserId(email);

  const deleteQuery=`DELETE FROM tasks WHERE id=? AND user_id=?`;
  await db.run(deleteQuery,[taskId,userId])

  response.status(200).send("Successfully Deleted")

})