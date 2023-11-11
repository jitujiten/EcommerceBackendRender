const { Order } = require("../model/Order");

exports.CreateOrder = async (req, res) => {
  const OrderItem = new Order(req.body);
  try {
    const doc = await OrderItem.save();
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.fetchOrderByUser = async (req, res) => {
  const { id } = req.user;
  try {
    const doc = await Order.find({ user: id });
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.updateOrder = async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await Order.findByIdAndUpdate(id, req.body, { new: true });
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.deleteOrder = async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await Order.findByIdAndDelete(id);
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json(err);
  }
};


exports.fetchAllOrders = async (req, res) => {
    let query = Order.find({deleted:{$ne:true}});
    let totalOrdersQuery = Order.find({deleted:{$ne:true}});
  
  
    if (req.query._sort && req.query._order) {
      query = query.sort({ [req.query._sort]: req.query._order });
    }
  
    const TotalDocs = await totalOrdersQuery.count().exec();
  
    if (req.query._page && req.query._limit) {
      const pageSize = req.query._limit;
      const page = req.query._page;
      query = query.skip(pageSize * (page - 1)).limit(pageSize);
    }
  
    try {
      const docs = await query.exec();
      res.set('X-Total-Count', TotalDocs); //set Used for send data in the header
      res.status(200).json(docs);
    } catch (err) {
      res.status(400).json(err);
    }
  };
