require("dotenv").config();
const express = require("express");
const server = express();
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const crypto = require("crypto");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");
const bodyParser = require("body-parser");

const ProductsRouters = require("./routes/Products");
const CategoriesRouters = require("./routes/Category");
const BrandRouters = require("./routes/Brand");
const UsersRouters = require("./routes/Users");
const AuthRouters = require("./routes/Auth");
const CartRouters = require("./routes/Cart");
const OrderRouters = require("./routes/Order");
const { User } = require("./model/User");
const { IsAuth, sanitiZeUser, cookieExtractor } = require("./services/common");
const { Order } = require("./model/Order");

//jwt option
const opts = {};
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = process.env.JWT_SECREET_KEY;

//middlewares
server.use(express.static(path.resolve(__dirname, "build")));

server.use(cookieParser());
server.use(bodyParser.json({ limit: "500kb" }));

server.use(
  session({
    secret: "keyboard cat",
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
  })
);
server.use(passport.authenticate("session"));

server.use(
  cors({
    exposedHeaders: ["X-Total-Count"],
  })
);

server.use(express.json()); //to parse req.body
server.use("/products", ProductsRouters.router); //to parse req.body
server.use("/category", CategoriesRouters.router);
server.use("/brands", BrandRouters.router);
server.use("/users", IsAuth(), UsersRouters.router);
server.use("/auth", AuthRouters.router);
server.use("/cart", IsAuth(), CartRouters.router);
server.use("/orders", IsAuth(), OrderRouters.router);

//passport strategies
passport.use(
  "local",
  new LocalStrategy({ usernameField: "email" }, async function (
    email,
    password,
    done
  ) {
    try {
      const user = await User.findOne({ email: email }).exec();
      if (!user) {
        return done(null, false, { message: "Invalid Credentials" });
      }

      crypto.pbkdf2(
        password,
        user.salt,
        310000,
        32,
        "sha256",
        async function (err, hashedPassword) {
          if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
            return done(null, false, { message: "Invalid Credentials" });
          }
          const token = jwt.sign(
            sanitiZeUser(user),
            process.env.JWT_SECREET_KEY
          );
          return done(null, {
            id: user.id,
            role: user.role,
            token,
            email: user.email,
            addresses: user.addresses,
            orders: user.orders,
            name: user.name,
            ProfileUrl: user.ProfileUrl,
          });
        }
      );
    } catch (err) {
      return done(err);
    }
  })
);

passport.use(
  "jwt",
  new JwtStrategy(opts, async function (jwt_payload, done) {
    try {
      const user = await User.findById(jwt_payload.id);
      if (user) {
        return done(null, {
          id: user.id,
          role: user.role,
          email: user.email,
          addresses: user.addresses,
          orders: user.orders,
          name: user.name,
          ProfileUrl: user.ProfileUrl,
        }); //this calls serializer
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  })
);

//this creates session variable req.user on being called from callbacks
//take user send  id
passport.serializeUser(function (user, cb) {
  console.log("serialize");
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      role: user.role,
      email: user.email,
      addresses: user.addresses,
      orders: user.orders,
      name: user.name,
      ProfileUrl: user.ProfileUrl,
    });
  });
});

//this creates session variable req.user when called from authorized request
//take id send  user

passport.deserializeUser(function (user, cb) {
  console.log("de-serialize");
  process.nextTick(function () {
    return cb(null, user);
  });
});

///payments
// This is your test secret API key.
const stripe = require("stripe")(process.env.STRIPE_KEY);

server.post("/create-payment-intent", async (req, res) => {
  const { totalAmount, OrderId } = req.body;

  if (!OrderId || !totalAmount) {
    return res
      .status(400)
      .send({ error: "Missing orderId or totalAmount in the request body" });
  }
  // Create a PaymentIntent with the order amount and currency
  const paymentIntent = await stripe.paymentIntents.create({
    amount: totalAmount * 100,
    currency: "inr",
    // In the latest version of the API, specifying the `automatic_payment_methods` parameter is optional because Stripe enables its functionality by default.
    automatic_payment_methods: {
      enabled: true,
    },
    metadata: {
      OrderId,
    },
  });

  res.send({
    clientSecret: paymentIntent.client_secret,
  });
});

///webhook

// This is your Stripe CLI webhook secret for testing your endpoint locally.
const endpointSecret = process.env.ENDPOINT_SECREET;

server.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (request, response) => {
    const sig = request.headers["stripe-signature"];

    let event;

    try {
      event = stripe.webhooks.constructEvent(request.body, sig, endpointSecret);
    } catch (err) {
      response.status(400).send(`Webhook Error: ${err.message}`);
      return;
    }

    // Handle the event
    switch (event.type) {
      case "payment_intent.succeeded":
        const paymentIntentSucceeded = event.data.object;
        const order = await Order.find(paymentIntentSucceeded.metadata.orderId);
        order.paymentStatus = "received";
        await order.save();
        // Then define and call a function to handle the event payment_intent.succeeded
        break;
      // ... handle other event types
      default:
        console.log(`Unhandled event type ${event.type}`);
    }

    // Return a 200 response to acknowledge receipt of the event
    response.send();
  }
);

main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect(process.env.MONGODB_URL);
  console.log("mongoose connected");
}

server.listen(process.env.PORT, () => {
  console.log("server started");
});
