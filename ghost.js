import React from 'react';

const ReactGaps = ({ userInput, userLink, userStyle }) => {

  // --- LEVEL 1: DANGEROUSLY SET HTML (The Classic) ---
  // React's explicit "I know what I'm doing" sink.
  const Level1 = () => (
    <div dangerouslySetInnerHTML={{ __html: userInput }} />
  );

  // --- LEVEL 2: SCRIPT INJECTION IN ATTRIBUTES ---
  // Bypasses JSX escaping by injecting into 'href'.
  // Attack: "javascript:alert('XSS')"
  const Level2 = () => (
    <a href={userLink}>Click Me</a>
  );

  // --- LEVEL 3: EVAL IN DISGUISE (setTimeout/Interval) ---
  // If userInput is a string, it acts like eval().
  const Level3 = () => {
    const runCode = () => {
        setTimeout(userInput, 1000); 
    };
    return <button onClick={runCode}>Run Task</button>;
  };

  // --- LEVEL 4: PROP SPREADING (The Stealthy One) ---
  // Spreading an untrusted object allows an attacker to inject
  // any attribute (onload, onerror, etc.) into the DOM element.
  // Attack: userInputObj = { "onerror": "alert(1)", "src": "x" }
  const Level4 = () => {
    const untrustedProps = JSON.parse(userInput);
    return <img {...untrustedProps} />;
  };

  // --- LEVEL 5: REF-BASED DOM MANIPULATION ---
  // Bypassing React entirely to touch the raw DOM. 
  // Scanners often miss this because the sink is 'innerHTML' on a 'ref'.
  const Level5 = () => {
    const myRef = React.useRef();
    
    React.useEffect(() => {
      myRef.current.innerHTML = userInput;
    }, [userInput]);

    return <div ref={myRef} />;
  };

  return <div>{/* Render levels */}</div>;
};
