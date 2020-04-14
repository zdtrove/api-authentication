const express = require('express');
const morgan = require('morgan');
const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost/api-authentication', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const app = express();

// Middlewares
app.use(express.json());
app.use(morgan('dev'));

// Routes
app.use('/users', require('./routes/users'));

// Start the server
const port = process.env.PORT || 5000;
app.listen(port);
console.log(`Server listening at port ${port}`);