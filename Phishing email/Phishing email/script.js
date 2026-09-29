let score = 0;

let checkedClues = {
    sender: false,
    urgency: false,
    link: false,
    language: false
};


// ==========================================
// CHECK PHISHING CLUES
// ==========================================

function checkClue(type) {

    if (checkedClues[type]) {

        showFeedback(
            "You have already checked this clue.",
            "normal"
        );

        return;
    }


    checkedClues[type] = true;


    let message = "";


    if (type === "sender") {

        message =
            "📧 Sender Check: Always inspect the complete sender address. Unexpected or unfamiliar domains should be treated carefully.";

        score += 20;
    }


    else if (type === "urgency") {

        message =
            "⏰ Urgency Check: Messages that pressure you to act immediately can be a phishing warning sign.";

        score += 20;
    }


    else if (type === "link") {

        message =
            "🔗 Link Check: Never click unexpected links. Verify the destination using a trusted method.";

        score += 20;
    }


    else if (type === "language") {

        message =
            "📝 Language Check: Unusual grammar, spelling, or wording can be a warning sign, although legitimate messages can also contain mistakes.";

        score += 20;
    }


    updateScore();

    showFeedback(
        message,
        "success"
    );
}


// ==========================================
// MAKE FINAL DECISION
// ==========================================

function makeDecision(decision) {

    if (decision === "phishing") {

        score += 20;

        updateScore();

        showFeedback(

            "🚨 Correct training response! This simulation contains warning signs. In a real situation, avoid interacting with suspicious content and report it through your organization's approved process.",

            "success"
        );

    }

    else {

        score = Math.max(
            0,
            score - 20
        );

        updateScore();

        showFeedback(

            "⚠️ Review the warning signs carefully. Unexpected urgency, unfamiliar senders, suspicious links, or unusual requests should be verified before taking action.",

            "error"
        );
    }
}


// ==========================================
// UPDATE SCORE
// ==========================================

function updateScore() {

    score = Math.min(
        100,
        score
    );

    document.getElementById(
        "score"
    ).textContent = score;


    document.getElementById(
        "progress"
    ).style.width = score + "%";
}


// ==========================================
// FEEDBACK
// ==========================================

function showFeedback(
    message,
    type
) {

    const feedback =
        document.getElementById(
            "feedback"
        );


    feedback.textContent =
        message;


    if (type === "success") {

        feedback.style.color =
            "#52e6b5";

        feedback.style.borderColor =
            "#16795e";
    }

    else if (type === "error") {

        feedback.style.color =
            "#ff8d8d";

        feedback.style.borderColor =
            "#8b3030";
    }

    else {

        feedback.style.color =
            "#75d7ff";

        feedback.style.borderColor =
            "#23527a";
    }
}