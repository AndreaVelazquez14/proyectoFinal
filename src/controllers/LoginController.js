const bcrypt = require('bcrypt');

function index(req, res) {
  if (req.session.loggedin) {
    // Output username
    res.redirect('/');

  } else {
    res.render('login/index');
  }
}

// function auth(req, res) {
//   const data = req.body;
//   req.getConnection((err, conn) => {
//     conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {
//       if (userdata.length > 0) {
//         res.render('login/register", { error: "Error: usuario ya existe!'});
//   } else {
//   }
// });
// });
// }

function register(req, res) {
  res.render('login/register');
}

function storeUser(req,res){
  const data = req.body;
  bcrypt.hash(data.password, 12).then(hash =>{
    data.password = hash;
    console.log(data)
  });
}

function auth(req, res) {
  let email = req.body.email;
  let password = req.body.password;

  req.getConnection((err, conn) => {
    conn.query('SELECT * FROM users WHERE email = ?', [email], (err, rows) => {
      if (rows.length > 0) {
        console.log(rows);
      } else {
        console.log('not');
      }
      /*
      req.session.loggedin = true;
  req.session.name = name;

  res.redirect('/');*/

    });
  });
}

function logout(req, res) {
  if (req.session.loggedin) {
    req.session.destroy();
  }
  res.redirect('/');
}


module.exports = {
  index: index,
  register: register,
  storeUser: storeUser,
  auth: auth,
  logout: logout,
}
