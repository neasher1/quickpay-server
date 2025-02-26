require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
// const bcrypt = require("bcrypt");
const bcrypt = require('bcryptjs');
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:5173", "https://quickpay-cash.netlify.app/"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// Database Connection
const MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.gxl79.mongodb.net/quickpay?retryWrites=true&w=majority&appName=Cluster0`;
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));


const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ["http://localhost:5173", "https://quickpay-cash.netlify.app/"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  }
});

io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

const sendNotification = async (userId, message) => {
  await Notification.create({ userId, message });
  io.emit(`notification-${userId}`, message);
};

const notifyAdmins = async (message) => {
  const admins = await User.find({ accountType: "admin" }).select("_id");
  admins.forEach((admin) => {
    sendNotification(admin._id.toString(), message);
  });
};


// User Schema
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  pin: { type: String, required: true },
  mobile: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  nid: { type: String, required: true, unique: true },
  accountType: {
    type: String,
    enum: ["user", "agent", "admin"],
    required: true,
  },
  balance: { type: Number, default: 0 },
  isApproved: { type: Boolean, default: false },
  isBlocked: { type: Boolean, default: false },
});
const User = mongoose.model("User", UserSchema);

// Transaction Schema
const TransactionSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  amount: { type: Number, required: true },
  transactionId: { type: String, unique: true, required: true },
  timestamp: { type: Date, default: Date.now },
  status: { type: String, enum: ["Completed", "Pending", "Failed"], default: "Completed" }
});
const Transaction = mongoose.model("Transaction", TransactionSchema);
module.exports = Transaction;

// Notification Schema
const NotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  isRead: { type: Boolean, default: false },
});
const Notification = mongoose.model("Notification", NotificationSchema);
module.exports = Notification;


// Notification Schema
const RequestSchema = new mongoose.Schema({
  agentId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, enum: ["cash-request", "withdraw-request"], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  createdAt: { type: Date, default: Date.now }
});
const Request = mongoose.model("Request", RequestSchema);
module.exports = Request;


// ** User Registration Route **
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, pin, mobile, email, accountType, nid } = req.body;

    const existingUser = await User.findOne({ $or: [{ mobile }, { email }, { nid }] });
    if (existingUser) {
      return res.status(400).json({ message: "User with this mobile, email, or NID already exists." });
    }

    const hashedPin = await bcrypt.hash(pin, 10);

    const initialBalance = accountType === "agent" ? 100000 : 40;

    const newUser = new User({
      name,
      pin: hashedPin,
      mobile,
      email,
      accountType,
      nid,
      balance: initialBalance,
      ...(accountType === "user" && { isApproved: true })
    });

    await newUser.save();

    res.status(201).json({ message: "Registration successful", userId: newUser._id });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ message: "Error registering user", error });
  }
});


// ** User Login Route **
app.post("/api/auth/login", async (req, res) => {
  try {
    const { identifier, pin } = req.body;

    const user = await User.findOne({ $or: [{ mobile: identifier }, { email: identifier }] });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(pin, user.pin);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id, accountType: user.accountType },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "Login successful", token, userId: user._id });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Error logging in", error });
  }
});


// ** Protected Route **
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
};

app.get("/api/users/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-pin");
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Error fetching user details" });
  }
});


// ** User Send Money **
app.post("/api/transactions/send-money", verifyToken, async (req, res) => {
  try {
    const { recipientMobile, amount } = req.body;
    const senderId = req.user.userId;

    if (amount < 50) {
      return res.status(400).json({ message: "Minimum amount to send is 50 Taka" });
    }

    const sender = await User.findById(senderId);
    const recipient = await User.findOne({ mobile: recipientMobile });
    const admin = await User.findOne({ accountType: "admin" });

    if (!recipient) return res.status(404).json({ message: "Recipient not found" });

    let sendFee = 0;
    if (amount > 100) {
      sendFee = 5;
    }

    const totalDeduction = amount + sendFee;
    if (sender.balance < totalDeduction) {
      return res.status(400).json({ message: "Insufficient balance" });
    }

    sender.balance -= totalDeduction;
    recipient.balance += amount;
    if (sendFee > 0) admin.balance += sendFee;

    const transaction = new Transaction({
      senderId,
      recipientId: recipient._id,
      amount,
      transactionId: `TXN${Date.now()}`,
      status: "Completed",
    });

    await sender.save();
    await recipient.save();
    await admin.save();
    await transaction.save();

    await sendNotification(senderId, `You sent ${amount} Taka to ${recipient.mobile}.`);
    await sendNotification(recipient._id, `You received ${amount} Taka from ${sender.mobile}.`);

    res.status(200).json({ message: "Transaction successful", transaction });
  } catch (error) {
    console.error("Transaction Error:", error);
    res.status(500).json({ message: "Transaction failed", error });
  }
});


// ** User Cash In **
app.post("/api/transactions/cash-in", verifyToken, async (req, res) => {
  try {
    const { agentMobile, amount, pin } = req.body;
    const userId = req.user.userId;

    const agent = await User.findOne({ mobile: agentMobile, accountType: "agent" });
    const user = await User.findById(userId);

    if (!agent) return res.status(404).json({ message: "Agent not found" });

    const isPinCorrect = await bcrypt.compare(pin, agent.pin);
    if (!isPinCorrect) return res.status(400).json({ message: "Invalid agent PIN" });

    if (agent.balance < amount) {
      return res.status(400).json({ message: "Agent does not have enough balance" });
    }

    user.balance += amount;
    agent.balance -= amount;

    const transaction = new Transaction({
      senderId: agent._id,
      recipientId: userId,
      amount,
      transactionId: `TXN${Date.now()}`,
      status: "Completed",
    });

    await user.save();
    await agent.save();
    await transaction.save();

    await sendNotification(userId, `You successfully cashed in ${amount} Taka through Agent ${agent.mobile}.`);

    res.status(200).json({ message: "Cash-In successful", balance: user.balance, transaction });
  } catch (error) {
    console.error("Cash-In Error:", error);
    res.status(500).json({ message: "Cash-in failed", error });
  }
});


// ** User Cash Out **
app.post("/api/transactions/cash-out", verifyToken, async (req, res) => {
  try {
    const { agentMobile, amount, pin } = req.body;
    const userId = req.user.userId;

    const user = await User.findById(userId);
    const agent = await User.findOne({ mobile: agentMobile, accountType: "agent" });

    if (!agent) return res.status(404).json({ message: "Agent not found" });

    const isPinCorrect = await bcrypt.compare(pin, user.pin);
    if (!isPinCorrect) return res.status(400).json({ message: "Invalid PIN" });

    const cashOutFee = amount * 0.015;
    const totalDeduction = amount + cashOutFee;

    if (user.balance < totalDeduction) {
      return res.status(400).json({ message: "Insufficient balance" });
    }

    user.balance -= totalDeduction;
    agent.balance += amount;

    const transaction = new Transaction({
      senderId: userId,
      recipientId: agent._id,
      amount,
      transactionId: `TXN${Date.now()}`,
      status: "Completed",
    });

    await user.save();
    await agent.save();
    await transaction.save();

    await sendNotification(userId, `You successfully withdrew ${amount} Taka through Agent ${agent.mobile}.`);

    res.status(200).json({ message: "Cash-Out successful", balance: user.balance, transaction });
  } catch (error) {
    console.error("Cash-Out Error:", error);
    res.status(500).json({ message: "Cash-out failed", error });
  }
});


// ** User transaction history **
app.get("/api/transactions/history", verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const transactions = await Transaction.find({
      $or: [{ senderId: userId }, { recipientId: userId }]
    })
      .populate("senderId", "name mobile")
      .populate("recipientId", "name mobile")
      .sort({ createdAt: -1 });

    const formattedTransactions = transactions.map((tx) => ({
      _id: tx._id,
      transactionId: tx.transactionId,
      senderId: tx.senderId ? { _id: tx.senderId._id, mobile: tx.senderId.mobile } : null,
      recipientId: tx.recipientId ? { _id: tx.recipientId._id, mobile: tx.recipientId.mobile } : null,
      amount: tx.amount,
      status: tx.status || "Completed",
      timestamp: tx.createdAt ? new Date(tx.createdAt).toISOString() : new Date().toISOString(),
      transactionType:
        tx.senderId?._id.toString() === userId.toString()
          ? tx.transactionType === "cash-out"
            ? "cash-out"
            : "sent"
          : tx.transactionType === "cash-in"
            ? "cash-in"
            : "received"
    }));

    res.status(200).json(formattedTransactions);
  } catch (error) {
    console.error("Fetch Transactions Error:", error);
    res.status(500).json({ message: "Failed to fetch transactions", error });
  }
});


// ** Fetch Notifications **
app.get("/api/notifications", verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const notifications = await Notification.find({ userId }).sort({ timestamp: -1 });
    res.status(200).json(notifications);
  } catch (error) {
    console.error("Notification Fetch Error:", error);
    res.status(500).json({ message: "Failed to fetch notifications", error });
  }
});

app.put("/api/notifications/read-all", verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    await Notification.updateMany({ userId, isRead: false }, { $set: { isRead: true } });
    res.status(200).json({ message: "All notifications marked as read" });
  } catch (error) {
    console.error("Error marking notifications as read:", error);
    res.status(500).json({ message: "Failed to mark notifications as read", error });
  }
});


// Admin Panel
// ** All Users for Admin Panel **
app.get("/api/admin/users", verifyToken, async (req, res) => {
  try {
    const admin = await User.findById(req.user.userId);
    if (admin.accountType !== "admin") {
      return res.status(403).json({ message: "Access Denied" });
    }

    const users = await User.find().select("-pin");
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: "Error fetching users", error });
  }
});

// ** Approve Agents **
app.post("/api/admin/approve-agent", verifyToken, async (req, res) => {
  try {
    const { agentId } = req.body;
    const admin = await User.findById(req.user.userId);
    if (admin.accountType !== "admin") {
      return res.status(403).json({ message: "Access Denied" });
    }

    const agent = await User.findById(agentId);
    if (!agent || agent.accountType !== "agent") {
      return res.status(404).json({ message: "Agent not found" });
    }

    agent.isApproved = true;
    await agent.save();

    res.status(200).json({ message: "Agent approved successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error approving agent", error });
  }
});


// ** Block User/Agents**
app.post("/api/admin/block-user", verifyToken, async (req, res) => {
  try {
    const { userId } = req.body;
    const admin = await User.findById(req.user.userId);
    if (admin.accountType !== "admin") {
      return res.status(403).json({ message: "Access Denied" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.isBlocked = true;
    await user.save();

    res.status(200).json({ message: "User blocked successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error blocking user", error });
  }
});

// ** pending cash & withdraw requests from agent**
app.get("/api/admin/pending-requests", verifyToken, async (req, res) => {
  try {
    const adminId = req.user.userId;
    const admin = await User.findById(adminId);

    if (!admin || admin.accountType !== "admin") {
      return res.status(403).json({ message: "Only admins can view pending requests" });
    }

    const pendingRequests = await Request.find({ status: "pending" }).populate("agentId", "name mobile balance");

    res.status(200).json(pendingRequests);
  } catch (error) {
    console.error("Fetch Pending Requests Error:", error);
    res.status(500).json({ message: "Failed to fetch pending requests", error });
  }
});


// ** Admin to Approve Requests**
app.put("/api/admin/approve-request/:requestId", verifyToken, async (req, res) => {
  try {
    const adminId = req.user.userId;
    const admin = await User.findById(adminId);

    if (!admin || admin.accountType !== "admin") {
      return res.status(403).json({ message: "Only admins can approve requests" });
    }

    const request = await Request.findById(req.params.requestId);
    if (!request) return res.status(404).json({ message: "Request not found" });

    if (request.status !== "pending") {
      return res.status(400).json({ message: "Request has already been processed" });
    }

    const agent = await User.findById(request.agentId);
    if (!agent) return res.status(404).json({ message: "Agent not found" });

    if (request.type === "cash-request") {
      agent.balance = (agent.balance || 0) + 100000;
    } else if (request.type === "withdraw-request") {
      if (agent.balance >= request.amount) {
        agent.balance -= request.amount;
      } else {
        return res.status(400).json({ message: "Agent does not have enough balance to withdraw." });
      }
    }

    request.status = "approved";
    await agent.save();
    await request.save();

    sendNotification(agent._id.toString(), `Your ${request.type.replace("-", " ")} request was approved.`);
    res.status(200).json({ message: "Request approved successfully. Agent balance updated.", balance: agent.balance });
  } catch (error) {
    console.error("Request Approval Error:", error);
    res.status(500).json({ message: "Failed to approve request", error });
  }
});


// ** Admin to Reject Requests**
app.put("/api/admin/reject-request/:requestId", verifyToken, async (req, res) => {
  try {
    const adminId = req.user.userId;
    const admin = await User.findById(adminId);

    if (!admin || admin.accountType !== "admin") {
      return res.status(403).json({ message: "Only admins can reject requests" });
    }

    const request = await Request.findById(req.params.requestId);
    if (!request) return res.status(404).json({ message: "Request not found" });

    if (request.status !== "pending") {
      return res.status(400).json({ message: "Request has already been processed" });
    }

    request.status = "rejected";
    await request.save();

    res.status(200).json({ message: "Request rejected successfully" });
  } catch (error) {
    console.error("Request Rejection Error:", error);
    res.status(500).json({ message: "Failed to reject request", error });
  }
});



// all users & agents
app.get("/api/admin/users", verifyToken, async (req, res) => {
  try {
    const adminId = req.user.userId;
    const admin = await User.findById(adminId);

    if (!admin || admin.accountType !== "admin") {
      return res.status(403).json({ message: "Only admins can view users" });
    }

    const users = await User.find().select("_id name mobile accountType balance");
    res.status(200).json(users);
  } catch (error) {
    console.error("Fetch Users Error:", error);
    res.status(500).json({ message: "Failed to fetch users", error });
  }
});


// search functionality in admin dashboard
app.get("/api/admin/users/search", verifyToken, async (req, res) => {
  try {
    const adminId = req.user.userId;
    const admin = await User.findById(adminId);

    if (!admin || admin.accountType !== "admin") {
      return res.status(403).json({ message: "Only admins can search users" });
    }

    const { mobile } = req.query;

    let filter = {};
    if (mobile) {
      filter.mobile = { $regex: mobile, $options: "i" };
    }

    const users = await User.find(filter).select("_id name mobile accountType balance");
    res.status(200).json(users);
  } catch (error) {
    console.error("Search Users Error:", error);
    res.status(500).json({ message: "Failed to search users", error });
  }
});



// transactions history for user/agents 
app.get("/api/admin/transactions/:userId", verifyToken, async (req, res) => {
  try {
    const adminId = req.user.userId;
    const admin = await User.findById(adminId);

    if (!admin || admin.accountType !== "admin") {
      return res.status(403).json({ message: "Only admins can view transactions of other users" });
    }

    const { userId } = req.params;
    const transactions = await Transaction.find({
      $or: [{ senderId: userId }, { recipientId: userId }]
    })
      .populate("senderId", "name mobile")
      .populate("recipientId", "name mobile")
      .sort({ createdAt: -1 });

    if (!transactions || transactions.length === 0) {
      return res.status(404).json({ message: "No transactions found for this user" });
    }

    res.status(200).json(transactions);
  } catch (error) {
    console.error("Fetch Transactions Error:", error);
    res.status(500).json({ message: "Failed to fetch transactions", error });
  }
});



// ** balance details based on user role**
app.get("/api/balance", verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    let response = { accountType: user.accountType };

    if (user.accountType === "user" || user.accountType === "agent") {
      response.balance = user.balance;
    }

    if (user.accountType === "admin") {
      const totalSystemBalance = await User.aggregate([{ $group: { _id: null, totalMoney: { $sum: "$balance" } } }]);
      response.totalMoney = totalSystemBalance.length ? totalSystemBalance[0].totalMoney : 0;
      response.adminIncome = user.balance;
    }

    res.status(200).json(response);
  } catch (error) {
    console.error("Balance Inquiry Error:", error);
    res.status(500).json({ message: "Failed to retrieve balance", error });
  }
});



// **Agent Panel **
// **Agent Requests a Balance Recharge **
app.post("/api/agent/cash-request", verifyToken, async (req, res) => {
  try {
    const agentId = req.user.userId;
    const agent = await User.findById(agentId);

    if (!agent || agent.accountType !== "agent") {
      return res.status(403).json({ message: "Only agents can request cash recharge" });
    }

    const request = new Request({
      agentId,
      type: "cash-request",
      amount: 100000,
    });

    await request.save();
    notifyAdmins(`Agent ${agent.mobile} requested 100,000 Taka cash recharge.`);

    res.status(200).json({ message: "Cash request submitted. Waiting for admin approval." });
  } catch (error) {
    console.error("Cash Request Error:", error);
    res.status(500).json({ message: "Failed to request cash", error });
  }
});


// **Agent Requests a Withdraw Request **
app.post("/api/agent/withdraw-request", verifyToken, async (req, res) => {
  try {
    const agentId = req.user.userId;
    const agent = await User.findById(agentId);

    if (!agent || agent.accountType !== "agent") {
      return res.status(403).json({ message: "Only agents can request withdrawal" });
    }

    if (agent.balance < 500) {
      return res.status(400).json({ message: "Minimum withdraw amount is 500 Taka" });
    }

    const request = new Request({
      agentId,
      type: "withdraw-request",
      amount: agent.balance,
    });

    await request.save();
    res.status(200).json({ message: "Withdraw request submitted. Waiting for admin approval." });
  } catch (error) {
    console.error("Withdraw Request Error:", error);
    res.status(500).json({ message: "Failed to request withdrawal", error });
  }
});

// agents transaction
app.get("/api/agent/transactions", verifyToken, async (req, res) => {
  try {
    const agentId = req.user.userId;
    const agent = await User.findById(agentId);

    if (!agent || agent.accountType !== "agent") {
      return res.status(403).json({ message: "Only agents can view their transactions" });
    }

    const requests = await Request.find({ agentId }).sort({ createdAt: -1 }).limit(100);

    const transactions = await Transaction.find({
      $or: [{ senderId: agentId }, { recipientId: agentId }]
    })
      .populate("senderId", "name mobile")
      .populate("recipientId", "name mobile")
      .sort({ createdAt: -1 })
      .limit(100);

    const fullHistory = [...requests, ...transactions].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.status(200).json(fullHistory.slice(0, 100));
  } catch (error) {
    console.error("Fetch Agent Transactions Error:", error);
    res.status(500).json({ message: "Failed to fetch transactions", error });
  }
});

app.get("/", (req, res) => {
  res.send("QuickPay Server");
});


app.listen(port, () => {
  console.log(`QuickPay Server is running on port ${port}`);
});
