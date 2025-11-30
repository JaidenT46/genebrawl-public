import {MovieClipHelper} from "../../titan/flash/MovieClipHelper";
import {TextField} from "../../titan/flash/TextField";
import {GameButton} from "../../titan/flash/gui/GameButton";
import {GenericPopup} from "../../titan/flash/gui/GenericPopup";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {Storage} from "../Storage";

export class OwnQuestionPopup extends GenericPopup {
    textField: TextField;
    buttons: GameButton[] = [];
    //okButton: GameButton;

    constructor(title: string, text: string) { // FIXME: don;t spawn at all! throws error about vtable. traash.
        super("popup_generic");

        //this.setTitle(title);
        const movieclip = this.getMovieClip();

        const titleField = movieclip.getTextFieldByName('title_txt')!;

        titleField.setText(title);

        this.textField = movieclip.getTextFieldByName('txt')!;

        this.textField.setText(text);

        MovieClipHelper.autoAdjustChildTexts(movieclip.instance);

        movieclip.setChildVisible("button_negative", false);
        movieclip.setChildVisible("button_no", false);
        movieclip.setChildVisible("button_yes", false);
        movieclip.setChildVisible("button_ok", false);

        this.closeButton = this.addButton("button_close", 1);

        this.closeButton.setButtonListener(new IButtonListener(this.okButtonClicked));

        const previousPopup = Storage.getPopup(this) ? Storage.getPopup(this) as OwnQuestionPopup : null;

        if (previousPopup) {
            previousPopup.fadeOut();
            Storage.removePopupByInstance(previousPopup.instance);
        }

        Storage.addPopup(this);
    }

    addCloseButton(exportName: string, text: string) {
        const self = this;
        const listener = new IButtonListener(() => {
            self.fadeOut();
            Storage.removePopupByInstance(self.instance);
        });

        const button = this.addButton(exportName, 1);
        button.setText(text);
        button.setButtonListener(listener);

        this.buttons.push(button);
    }

    addPopupButton(exportName: string, text: string, listener: IButtonListener) {
        const button = this.addButton(exportName, 1);
        button.setText(text);
        button.setButtonListener(listener);

        this.buttons.push(button);
    }

    private okButtonClicked(listener: NativePointer, button: NativePointer) {
        const popup = Storage.popups.find(e => e instanceof OwnQuestionPopup) as OwnQuestionPopup;

        popup.fadeOut();
        Storage.removePopupByInstance(popup.instance);
    }
}