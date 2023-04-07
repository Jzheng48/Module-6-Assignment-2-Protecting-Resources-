const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticateUser, authorizeUser } = require('./middleware');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
const bodyParser = require('body-parser');
app.use(bodyParser.json());



const userschema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
});

userschema.pre('save', async function(next) {
  const user = this;
  if (!user.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(user.password, salt);
  user.password = hash;
  next();
});

const User = mongoose.model('User', userschema);

app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = new User({ email, password });
    await user.save();
    res.json({
      success: true,
      message: 'User registered successfully',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'An error occurred',
    });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
  
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email or password',
      });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email or password',
      });
    }
    const token = jwt.sign({ userId: user._id, role: user.role }, 'secret', {
      //noTimestamp:true,
      expiresIn: '10d'//process.env.JWT_EXPIRES_IN
    });
    const cookieOptions = {
      expires: new Date(
        Date.now() + 10*24 * 60 * 60 * 1000 //process.env.JWT_COOKIE_EXPIRES_IN * 
      ),
      httpOnly: true
    };
    res.cookie('jwt', token, cookieOptions);
    res.json({
      success: true,
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'An error occurred',
    });
  }
});

app.get('/protected', authenticateUser, authorizeUser(['admin']), (req, res) => {
  const token=req.headers.authorization;
    res.json({
      success: true,
      message: 'You have accessed a protected resource',
    });
  });
  
//asyncronous connection
mongoose.connect('mongodb+srv://jiaweizheng:88888888@cluster0.buoixrx.mongodb.net/test', {useNewUrlParser: true})
    .then(() => console.log('MondoDB connection successful'))
    .catch((err) => console.error(err));

//start the server
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`App running on port ${port}...`);
});
