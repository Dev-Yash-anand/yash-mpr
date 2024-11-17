   const mongoose = require('mongoose');
   require('dotenv').config();
   const uri = process.env.MONGODB_URI; 
   
   // Connect to MongoDB
   mongoose.connect(uri)
       .then(() => {
           console.log('MongoDB connected successfully');
       })
       .catch(err => {
           console.error('MongoDB connection error:', err);
       });

   module.exports = mongoose.connection;