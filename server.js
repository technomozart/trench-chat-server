const express = require("express");
const http = require("http");
const { Server } = require("socket.io");


const app = express();
const server = http.createServer(app);


const io = new Server(server, {
cors: { origin: "*" }
});


// in-memory chat history
// { CA: [ { user, avatar, text, time } ] }
const history = {};


io.on("connection", (socket) => {
console.log("User connected:", socket.id);


socket.on("join_room", (room) => {
socket.join(room);


// send history to user
if (history[room]) {
socket.emit("chat_history", history[room]);
}
});


socket.on("send_message", ({ room, message }) => {
const msg = {
...message,
time: Date.now()
};


if (!history[room]) history[room] = [];
history[room].push(msg);


// limit history size (optional safety)
if (history[room].length > 200) {
history[room].shift();
}


io.to(room).emit("receive_message", msg);
});


socket.on("disconnect", () => {
console.log("User disconnected:", socket.id);
});
});


server.listen(3000, () => {
console.log("Server running at http://localhost:3000");
});