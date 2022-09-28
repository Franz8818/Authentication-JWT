const getState = ({
    getStore,
    getActions,
    setStore
}) => {
    return {
        store: {
            demo: [{
                    title: "FIRST",
                    background: "white",
                    initial: "white"
                },
                {
                    title: "SECOND",
                    background: "white",
                    initial: "white"
                }
            ],
            auth: false,
            perfil: {}
        },
        actions: {
            // Use getActions to call a function within a fuction
            exampleFunction: () => {
                getActions().changeColor(0, "green");
            },
            loadSomeData: () => {
                /**
                	fetch().then().then(data => setStore({ "foo": data.bar }))
                */
            },
            login: (email, password) => {
                /**
                	fetch().then().then(data => setStore({ "foo": data.bar }))
                */
                fetch('https://3000-purple-sawfish-rn2q66p2peu.ws-eu67.gitpod.io/login', {
                        method: "POST",
                        body: JSON.stringify({
                            email: email,
                            password: password
                        }),
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    })
                    .then((response) => {
                        if (response.status === 200) {
                            setStore({
                                auth: true
                            })
                        }
                        return response.json()
                    })
                    // .then((data) => console.log(data))
                    .then((data) => localStorage.setItem("token", data.access_token))

            },
            logout: () => {
                localStorage.removeItem('token');
                setStore({
                    auth: false
                })

            },
            getProfile: () => {
                let token = localStorage.getItem("token");
                fetch('https://3000-purple-sawfish-rn2q66p2peu.ws-eu67.gitpod.io/profile', {
                        method: "GET",
                        headers: {
                            'Content-Type': 'application/json',
                            Authorization: 'Bearer ' + token
                        }
                    })
                    .then((response) => {
                        // if (response.status === 200) {
                        //     setStore({
                        //         auth: true
                        //     })
                        // }
                        return response.json()
                    })
                    .then((data) => setStore({
                        perfil: data
                    }))
                // .then((data) => localStorage.setItem("token", data.access_token))

            },
            changeColor: (index, color) => {
                //get the store
                const store = getStore();

                //we have to loop the entire demo array to look for the respective index
                //and change its color
                const demo = store.demo.map((elm, i) => {
                    if (i === index) elm.background = color;
                    return elm;
                });

                //reset the global store
                setStore({
                    demo: demo
                });
            }
        }
    };
};

export default getState;