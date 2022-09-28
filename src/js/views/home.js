import React, { useState, useContext } from "react";
import { Context } from "../store/appContext";
import { Redirect } from "react-router-dom";
import "../../styles/home.css";

export const Home = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { store, actions } = useContext(Context);
  // const navigate = useNavigate();

  const handleSubmit = (e) => {
    e.preventDefault();
    actions.login(email, password);
  };

  return (
    <div className="text-center mt-5">
      {store.auth ? (
        <Redirect to="/demo" />
      ) : (
        <form className="w-50 mx-auto" onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="exampleInputEmail1" className="form-label">
              Email address
            </label>
            <input
              type="email"
              className="form-control"
              id="exampleInputEmail1"
              aria-describedby="emailHelp"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="mb-3">
            <label htmlFor="exampleInputPassword1" className="form-label">
              Password
            </label>
            <input
              type="password"
              className="form-control"
              id="exampleInputPassword1"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-primary">
            Submit
          </button>
        </form>
      )}
    </div>
  );
};
