const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

function login(req, res) {
  if (req.session.loggedin != true) {
    res.render('login/index');
  } else {
    res.redirect('/');
  }
}

function resetPassword(req, res) {
  const data = req.body;
  const newPassword = req.body.newPassword; // Obtener la nueva contraseña del cuerpo de la solicitud

  req.getConnection((err, conn) => {
    if (err) {
      console.error('Error al establecer la conexión: ' + err.stack);
      return res.render('login/resetPassword', { error: 'Error de conexión a la base de datos' });
    }

    conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {
      if (err) {
        console.error('Error al realizar la consulta: ' + err.stack);
        return res.render('login/resetPassword', { error: 'Error al consultar la base de datos' });
      }

      if (userdata.length > 0) {
        const user = userdata[0]; // Obtener el primer usuario encontrado

        if (data.securityQuestion === user.securityQuestion && data.securityAnswer === user.securityAnswer) {
          const hashedPassword = bcrypt.hashSync(newPassword, 10); // Hashear la nueva contraseña

          conn.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, data.email], (err, result) => {
            if (err) {
              console.error('Error al actualizar la contraseña: ' + err.stack);
              return res.render('login/resetPassword', { error: 'Error al actualizar la contraseña' });
            }

            req.session.loggedin = true;
            req.session.name = user.name;
            return res.redirect('/');
          });
        } else {
          return res.render('login/resetPassword', { error: 'Respuesta incorrecta o pregunta de seguridad inválida' });
        }
      } else {
        return res.render('login/resetPassword', { error: 'Usuario no encontrado' });
      }
    });
  });
}





function auth(req, res) {
  const data = req.body;

  req.getConnection((err, conn) => {
    conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {

      if (userdata.length > 0) {

        userdata.forEach(element => {
          bcrypt.compare(data.password, element.password, (err, isMatch) => {

            if (!isMatch) {
              res.render('login/index', { error: 'Contrasena incorrecta' });
            } else {
              req.session.loggedin = true;
              req.session.name = element.name;
              res.redirect('/');
            }
          });
        });

      } else {
        res.render('login/index', { error: 'Usuario no encontrado' });
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

  // Hash de la contraseña
  bcrypt.hash(data.password, 12)
    .then(hash => {
      data.password = hash;

      // Aquí deberías utilizar tu conexión a la base de datos para realizar la inserción
      req.getConnection((err, conn) => {
        if (err) {
          console.error('Error al conectar a la base de datos: ' + err.stack);
          return;
        }

        conn.query('INSERT INTO users SET ?', [data], (err, result) => {
          if (err) {
            console.error('Error al realizar la inserción en la base de datos: ' + err.stack);
            return;
          }

          req.session.loggedin = true;
          req.session.name = data.name;

          res.redirect('/');
        });
      });
    })
    .catch(err => {
      console.error('Error al generar el hash de la contraseña: ' + err.stack);
      res.redirect('/');
    });
}


function logout(req, res) {
  if (req.session.loggedin) {
    req.session.destroy();
  }
  res.redirect('/');
}

// Consulta usuarios
function administrar(req, res) {
  req.getConnection((err, conn) => {
    if (err) {
      console.error('Error al conectar a la base de datos: ' + err.stack);
      return;
    }

    conn.query('SELECT * FROM users', (err, userdata) => {
      if (err) {
        console.error('Error al realizar la consulta: ' + err.stack);
        return;
      }

      // Renderizar la vista 'administrar' y pasar los datos de la consulta como contexto
      res.render('login/administrar', { usuarios: userdata });
    });
  });
}


module.exports = {
  login,
  register,
  storeUser,
  auth,
  logout,
  administrar,
  resetPassword
}