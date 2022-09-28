import React, {useContext} from "react";
import {Context} from "../store/appContext"
import { Link, useHistory } from "react-router-dom";

export const Navbar = () => {
	const {store,actions}=useContext(Context)
	let history = useHistory();

	const handleLogout = ()=>{
		actions.logout()
		if(!store.auth){//true
			history.push("/")
		}
	}

	return (
		<nav className="navbar navbar-light bg-light mb-3">
			<Link to="/">
				<span className="navbar-brand mb-0 h1">React Boilerplate</span>
			</Link>
			<div className="ml-auto">
				{/* <Link to="/demo"> */}
				{store.auth?<button className="btn btn-primary" onClick={handleLogout}>Log out</button>:null}
					
				{/* </Link> */}
			</div>
		</nav>
	);
};
