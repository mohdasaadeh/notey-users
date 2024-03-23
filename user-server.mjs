import restify from "restify";
import * as util from "util";
import DBG from "debug";
import { default as bcrypt } from "bcrypt";

import {
  SQUser,
  connectDB,
  userParams,
  findOneUser,
  createUser,
  sanitizedUser,
} from "./users-sequelize.mjs";

const log = DBG("users:service");
const error = DBG("users:error");

const server = restify.createServer({
  name: "User-Auth-Service",
  version: "0.0.1",
});

server.use(restify.plugins.authorizationParser());
server.use(check);
server.use(restify.plugins.queryParser());
server.use(
  restify.plugins.bodyParser({
    mapParams: true,
  })
);

server.post("/create-user", (req, res, next) => {
  connectDB()
    .then(() => {
      createUser(req).then((result) => {
        res.contentType = "json";
        res.send(result);

        next(false);
      });
    })
    .catch((error) => {
      console.log(error);

      res.send(500, error);

      next(false);
    });
});

server.post("/find-or-create", (req, res, next) => {
  connectDB()
    .then(() => {
      findOneUser(req.params.username).then((user) => {
        if (!user) {
          createUser(req).then((user) => {
            if (!user) {
              throw new Error("No user created");
            }
          });
        }

        res.contentType = "json";
        res.send(user);

        return next(false);
      });
    })
    .catch((error) => {
      res.send(500, error);

      next(false);
    });
});

server.get("/find/:username", (req, res, next) => {
  connectDB()
    .then(() => {
      findOneUser(req.params.username).then((user) => {
        if (!user) {
          res.send(404, new Error("Did not find " + req.params.username));
        } else {
          res.contentType = "json";
          res.send(user);
        }
        next(false);
      });
    })
    .catch((error) => {
      res.send(500, error);

      next(false);
    });
});

server.get("/list", (req, res, next) => {
  connectDB()
    .then(() => {
      SQUser.findAll({}).then((userList) => {
        let userListMapped = userList.map((u) => sanitizedUser(u));

        if (!userList) {
          userListMapped = [];
        }

        res.contentType = "json";
        res.send(userListMapped);

        next(false);
      });
    })
    .catch((error) => {
      console.log(error);

      res.send(500, error);

      next(false);
    });
});

server.post("/update-user/:username", (req, res, next) => {
  connectDB()
    .then(() => {
      const toupdate = userParams(req);

      SQUser.update(toupdate, {
        where: { username: req.params.username },
      }).then(() => {
        findOneUser(req.params.username).then((result) => {
          console.log(result);

          res.contentType = "json";
          res.send(result);

          next(false);
        });
      });
    })
    .catch((error) => {
      res.send(500, error);

      next(false);
    });
});

server.del("/destroy/:username", (req, res, next) => {
  connectDB()
    .then(() => {
      SQUser.findOne({
        where: { username: req.params.username },
      }).then((user) => {
        if (!user) {
          res.send(
            404,
            new Error(`Did not find requested ${req.params.username} to delete`)
          );
        } else {
          user.destroy();

          res.contentType = "json";
          res.send({});
        }

        next(false);
      });
    })
    .catch((error) => {
      res.send(500, error);
      next(false);
    });
});

server.post("/password-check", (req, res, next) => {
  connectDB()
    .then(() => {
      SQUser.findOne({
        where: { username: req.params.username },
      }).then((user) => {
        let checked;

        console.log(user);

        if (!user) {
          checked = {
            check: false,
            username: req.params.username,
            message: "Could not find user",
          };

          res.contentType = "json";
          res.send(checked);

          next(false);
        } else {
          if (user.username === req.params.username) {
            bcrypt
              .compare(req.params.password, user.password)
              .then((result) => {
                if (result) {
                  checked = { check: true, username: user.username };
                } else {
                  checked = {
                    check: false,
                    username: req.params.username,
                    message: "Incorrect username or password",
                  };
                }

                res.contentType = "json";
                res.send(checked);

                next(false);
              });
          }
        }
      });
    })
    .catch((error) => {
      res.send(500, error);

      next(false);
    });
});

server.listen(
  process.env.PORT,
  process.env.REST_LISTEN ? process.env.REST_LISTEN : "localhost",
  function () {
    log(server.name + " listening at " + server.url);
  }
);

process.on("uncaughtException", function (err) {
  console.error("UNCAUGHT EXCEPTION - " + (err.stack || err));

  process.exit(1);
});

process.on("unhandledRejection", (reason, p) => {
  console.error(`UNHANDLED PROMISE REJECTION: ${util.inspect(p)}
reason: ${reason}`);

  process.exit(1);
});

// Mimic API Key authentication.
const apiKeys = [{ user: "them", key: "D4ED43C0-8BD6-4FE2-B358-7C0E230D11EF" }];

function check(req, res, next) {
  if (req.authorization && req.authorization.basic) {
    let found = false;

    for (let auth of apiKeys) {
      if (
        auth.key === req.authorization.basic.password &&
        auth.user === req.authorization.basic.username
      ) {
        found = true;

        break;
      }
    }

    if (found) {
      next();
    } else {
      res.send(401, new Error("Not authenticated"));

      next(false);
    }
  } else {
    res.send(500, new Error("No Authorization Key"));

    next(false);
  }
}
