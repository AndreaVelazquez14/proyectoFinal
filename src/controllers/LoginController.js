const bcrypt = require('bcrypt');

function login(req, res) {
  if (req.session.loggedin != true) {
    res.render('login/index');
  } else {
    res.redirect('/');
  }
}

function auth(req, res) {
  const data = req.body;

  req.getConnection((err, conn) => {
    conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {

      if (userdata.length > 0) {

        userdata.forEach(element => {
          bcrypt.compare(data.password, element.password, (err, isMatch) => {

            if (!isMatch) {
              res.render('login/index', { error: 'Error: Contrasena incorrecta' });
            } else {
              req.session.loggedin = true;
              req.session.name = element.name;
              res.redirect('/');
            }
          });
        });

      } else {
        res.render('login/index', { error: 'Error: Usuario no existe' });
      }
    });
  });
}

function register(req, res) {
  if (req.session.loggedin != true) {

    res.render('login/register');
  } else {
    res.redirect('/');
  }
}

function storeUser(req, res) {
  const data = req.body;

  req.getConnection((err, conn) => {
    conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {
      if (userdata.length > 0) {
        res.render('login/register', { error: 'Error: Usuario ya existe' });
      } else {
        bcrypt.hash(data.password, 12).then(hash => {
          data.password = hash;
          req.getConnection((err, conn) => {
            conn.query('INSERT INTO users SET ?', [data], (err, rows) => {
              req.session.loggedin = true;
              req.session.name = data.name;
              
              res.redirect('/');
            });
          });
        });
      }
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
  login,
  register,
  storeUser,
  auth,
  logout,
}
