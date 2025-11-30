import {GameMain} from "../../laser/client/GameMain";
import {ResourceManager} from "../../titan/ResourceManager";
import {MovieClip} from "../../titan/flash/MovieClip";
import {MovieClipHelper} from "../../titan/flash/MovieClipHelper";
import {Stage} from "../../titan/flash/Stage";
import {Resources} from "../Resources";

export class SpeechCharacter extends MovieClip {
    private bubble: MovieClip;
    private timeout: ReturnType<typeof setTimeout> = setTimeout(() => { }, 0);

    constructor(text: string) {
        const speechMc = ResourceManager.getMovieClip(Resources.UI, "tutorial_character_top");
        super(speechMc.instance);

        const bubble = ResourceManager.getMovieClip(Resources.UI, "tutorial_text_top");

        const movieClip = this;

        const appearStart = movieClip.getFrameIndex("AppearStart");
        const appearEnd = movieClip.getFrameIndex("AppearEnd");
        movieClip.gotoAndPlayFrameIndex(appearStart, appearEnd);

        const bubbleAppearStart = bubble.getFrameIndex("AppearStart");
        const bubbleAppearEnd = bubble.getFrameIndex("AppearEnd");
        bubble.gotoAndPlayFrameIndex(bubbleAppearStart, bubbleAppearEnd);

        const bubbleMc = bubble.getChildByName("bubble");
        const textField = bubbleMc.getTextFieldByName("text")!;

        MovieClipHelper.setTextAndScaleIfNecessary(textField, text);

        const textHeight = textField.getTextHeight();
        const textFieldY = textField.y;

        textField.y = ((textHeight * -0.5) + 40) + textFieldY;
        const child = movieClip.getChildByName("bubble");
        child.addChild(bubble);

        this.bubble = bubble;

        // просчёт координат (надо от правого края )

        const x = Stage.getX() * 2 - this.getWidth() / 2;
        const y = this.getHeight() / 2;

        this.setXY(x, y);
    }

    hideAfter(seconds: number) {
        if (this.timeout) {
            clearTimeout(this.timeout);
        }

        this.timeout = setTimeout(this.goAway.bind(this), seconds * 1000);
    }

    goAway() {
        const disappearStart = this.getFrameIndex("DisappearStart");
        const disappearEnd = this.getFrameIndex("DisappearEnd");
        this.gotoAndPlayFrameIndex(disappearStart, disappearEnd);

        const bubbleDisappearStart = this.bubble.getFrameIndex("DisappearStart");
        const bubbleDisappearEnd = this.bubble.getFrameIndex("DisappearEnd");
        this.bubble.gotoAndPlayFrameIndex(bubbleDisappearStart, bubbleDisappearEnd);

        while (true) {
            if (bubbleDisappearEnd === this.bubble.getCurrentFrame()) {
                GameMain.getHomeSprite().removeChild(this);
                break;
            }
        }
    }

    setText(text: string) {
        const bubbleMc = this.bubble.getChildByName("bubble");
        const textField = bubbleMc.getTextFieldByName("text")!;

        MovieClipHelper.setTextAndScaleIfNecessary(textField, text);
    }
}