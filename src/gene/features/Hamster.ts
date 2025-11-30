import {GameButton} from "../../titan/flash/gui/GameButton";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {MovieClip} from "../../titan/flash/MovieClip";
import {TextField} from "../../titan/flash/TextField";
import {ResourceManager} from "../../titan/ResourceManager";
import {Mathematics} from "../../utils/Mathematics";
import {Debug} from "../Debug";
import {DebugMenuBase} from "../debug/DebugMenuBase";
import {ToggleDebugClickerButton} from "../debug/ToggleDebugClickerButton";
import {Resources} from "../Resources";
import {EvolutionData, HamsterData, ItemData} from "./hamster/Data";
import {RGBA} from "./RGBA";

interface HamsterSaveData {
    clicks: number,
    purchasedItems: Array<ItemData>,
    currentEvolution: EvolutionData,
    currentEnergy: number,
    sinceLastClick: number;
}

export class Hamster extends DebugMenuBase { // я обязательно вернусь к этому --tailsjs (предлагаю провести опрос че лучше сделать сначала)
    private readonly hamsterButton: GameButton;
    private readonly toggleDebugClickerButton: ToggleDebugClickerButton;
    private textField: TextField;

    private save: HamsterSaveData = {
        clicks: 0,
        purchasedItems: [], // I guess we need to store here automatic drochilki
        currentEvolution: HamsterData.getEvolutionData()[0],
        currentEnergy: 1000,
        sinceLastClick: Mathematics.getTimestamp()
    };

    // TODO: evolutions, trade clicks to some bonuskas, da, pizda. - tailsjs

    constructor() {
        super("preview_menu");

        this.setTitle("genemoe");

        this.loadSaveData();
        this.encountEnergyRestorationAmount();

        this.toggleDebugClickerButton = new ToggleDebugClickerButton();
        this.toggleDebugClickerButton.setMovieClip(this.movieClip.getChildByName("close_button"));

        const previewArea = this.movieClip.getChildByName("preview_area");
        const mainMovieClip = ResourceManager.getMovieClip(Resources.DEBUG, "debug_menu_text");

        this.textField = mainMovieClip.getTextFieldByName("Text")!; // TODO: Import better text
        const movieClipD = new MovieClip(this.textField?.instance as NativePointer);

        movieClipD.setXY(18, 7);

        this.textField?.setText(`Clicks: ${this.save.clicks}`);
        this.textField?.setFontSize(72);
        this.textField?.setScale(0.06);
        this.textField?.setTextColor(RGBA.purple);

        const emojiMovieClip = ResourceManager.getMovieClip(Resources.EMOJI, this.save.currentEvolution.emoji);

        emojiMovieClip.setXY(25, 25);
        emojiMovieClip.setScale(0.3);
        emojiMovieClip.playOnce();
        emojiMovieClip.setFrame(2);

        this.hamsterButton = new GameButton();

        this.hamsterButton.setMovieClip(emojiMovieClip);
        this.hamsterButton.setButtonListener(new IButtonListener(this.click));

        this.movieClip.addChild(this.toggleDebugClickerButton);
        previewArea.addChild(movieClipD);
        previewArea.addChild(this.hamsterButton);
    }

    click() {
        const hamsterContext = Debug.getHamster();

        if (hamsterContext.save.currentEnergy <= 0) return;

        hamsterContext.addClicks(hamsterContext.save.currentEvolution.clicksPerClick);
        hamsterContext.wasteEnergy(HamsterData.energyRestorationAmount); // :trollface:
        hamsterContext.updateText(`Clicks: ${hamsterContext.getClicks()}`);
    }

    getClicks() {
        return this.save.clicks;
    }

    encountEnergyRestorationAmount() {
        if (this.save.currentEnergy >= this.save.currentEvolution.maxEnergy) return;

        const energyAmount = Math.round((Mathematics.getTimestamp() - this.save.sinceLastClick) / HamsterData.energyRestorationCooldown);

        if (energyAmount < 1) return;

        this.save.sinceLastClick = Mathematics.getTimestamp();

        this.restoreEnergy(energyAmount * HamsterData.energyRestorationAmount);
    }

    restoreEnergy(amount: number) {
        this.save.currentEnergy = Mathematics.getMaxIfHigher(this.save.currentEnergy + amount, this.save.currentEvolution.maxEnergy);
    }

    wasteEnergy(amount: number) {
        this.save.currentEnergy = Mathematics.getMinIfLower(this.save.currentEnergy - amount, 0);
    }

    addClicks(clicks: number) {
        this.save.clicks += clicks;
        this.save.sinceLastClick = Mathematics.getTimestamp();
        const hamsterButton = this.hamsterButton.getMovieClip();
        /*hamsterButton.setScale(0.36)
        setTimeout(function() {
            hamsterButton.setScale(0.3)
        }, 50)*/
    }

    updateText(text: string) {
        this.textField?.setText(text);
    }

    updateProgressBar() {
        const progressBarPercentage = Mathematics.percentage(this.save.currentEnergy, this.save.currentEvolution.maxEnergy);

        // TODO: ProgressBar
    }

    toggle() {
        super.toggle();

        if (this.visibility)
            this.hamsterButton.getMovieClip().playOnce();
    }

    mergeIntoMainSaveData() {
        // TODO: Merging hamster save data into genebrawl save data
        // maybe encrypt it?
    }

    loadSaveData() {
        // TODO: Loading hamster save data from genebrawl save data
    }
}