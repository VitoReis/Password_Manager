import sys
from pyperclip import copy
from os import listdir, remove, mkdir
from os.path import exists
from secrets import choice
from string import ascii_lowercase, ascii_uppercase, digits
from re import findall, DOTALL, escape, sub
from cryptography.fernet import Fernet
from tkinter import StringVar
from customtkinter import CTk, CTkLabel, CTkButton, CTkEntry, CTkFrame, CTkToplevel, CTkScrollableFrame, CTkRadioButton, CTkCheckBox


class App(CTk):
    def __init__(self):
        super().__init__()

        # WINDOW
        self.title("Gerenciador de senhas")
        self.geometry(f"{800}x{600}")
        self._set_appearance_mode("dark")
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=2)
        if not exists("profiles"):
            mkdir("profiles")
        self.__profiles = listdir("profiles")
        self.__open_profile = {}

        # SIDEBAR
        self.sidebar_frame = CTkFrame(self, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, padx=(0, 2), sticky="nswe")
        self.sidebar_frame.rowconfigure(0, weight=0)
        self.sidebar_frame.rowconfigure(1, weight=1)
        self.sidebar_frame.grid_columnconfigure(0, weight=1)

        self.profile_label = CTkLabel(self.sidebar_frame, text="Perfis:", font=("Helvetica bold", 25))
        self.profile_label.grid(row=0, pady=(10, 0))

        self.__update_profiles()

        # MAIN CONTENT
        self.content_frame = CTkFrame(self, corner_radius=0)
        self.content_frame.grid(row=0, column=1, sticky="nswe")
        self.content_frame.rowconfigure(0, weight=1)
        self.content_frame.columnconfigure(0, weight=1)

        self.content_title_label = CTkLabel(self.content_frame, text="Selecione um perfil", font=("Helvetica bold", 35), corner_radius=15)
        self.content_title_label.grid(row=0, column=0, padx=10, pady=10, sticky="nswe")

        # BOTTOM
        self.bottom_frame = CTkFrame(self, corner_radius=0)
        self.bottom_frame.grid(row=1, column=0, columnspan=2, pady=(2, 0), sticky="nswe")
        self.bottom_frame.rowconfigure(0, weight=1)
        self.bottom_frame.columnconfigure((0, 1, 2, 3), weight=1)

        self.add_profile_button = CTkButton(self.bottom_frame, text="Adicionar novo perfil", font=("Helvetica bold", 14), width=150, command=self.__add_new_profile)
        self.add_profile_button.grid(row=0, column=0, padx=5, pady=10)

        self.__delete_profile_button = CTkButton(self.bottom_frame, text="Deletar perfil selecionado", font=("Helvetica bold", 14), width=150, command=self.__delete_profile)
        self.__delete_profile_button.grid(row=0, column=1, padx=5, pady=10)
        self.__delete_profile_button.configure(state="disabled", cursor="arrow", fg_color="grey")

        self.new_password_button = CTkButton(self.bottom_frame, text="Adicionar nova senha", font=("Helvetica bold", 14), width=150, command=self.__add_new_password)
        self.new_password_button.grid(row=0, column=2, padx=5, pady=10)
        self.new_password_button.configure(state="disabled", cursor="arrow", fg_color="grey")

        self.__delete_password_button = CTkButton(self.bottom_frame, text="Deletar uma senha", font=("Helvetica bold", 14), width=150, command=self.__delete_password)
        self.__delete_password_button.grid(row=0, column=3, padx=5, pady=10)
        self.__delete_password_button.configure(state="disabled", cursor="arrow", fg_color="grey")

    def __add_new_profile(self):
        self.__delete_content_childrens()
        frame = CTkFrame(self.content_frame, corner_radius=15)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nswe")
        frame.grid_rowconfigure((0, 1, 2), weight=1)
        frame.grid_columnconfigure((0, 1), weight=1)

        text_label = CTkLabel(frame, text="Insira o nome do novo perfil:", font=("Helvica bold", 25))
        text_label.grid(row=0, column=0, columnspan=2, padx=20, pady=10, sticky="nswe")

        name_entry = CTkEntry(frame, placeholder_text="Nome")
        name_entry.grid(row=1, column=0, columnspan=2)

        confirm_button = CTkButton(frame, text="Adicionar", command=lambda: self.__confirm_profile_creation(name_entry.get()))
        confirm_button.grid(row=2, column=0, padx=10, pady=10)

        cancel_button = CTkButton(frame, text="Cancelar", command=frame.destroy)
        cancel_button.grid(row=2, column=1, padx=10, pady=10)

    def __confirm_profile_creation(self, profile):
        profiles_list = []
        for p in self.__profiles:
            profiles_list.append(p.lower())
        if profile != "" and not profile.lower() in profiles_list:
            self.__delete_content_childrens()
            key = Fernet.generate_key()
            fernet = Fernet(key)
            with open(f"profiles/{profile}", "w+b") as file:
                file.write(fernet.encrypt(file.read()))
            self.__show_encryption_key(key)
            self.__profiles.append(profile)
            self.__update_profiles()
        else:
            self.__show_error(3)

    def __show_encryption_key(self, key):
        frame = CTkFrame(self.content_frame, corner_radius=15)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nswe")
        frame.grid_rowconfigure((0, 1), weight=1)
        frame.grid_rowconfigure(2, weight=2)
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure((0, 1), weight=1)

        key_title_label = CTkLabel(frame, text="ATENÇÃO", font=("Helvica bold", 25))
        key_title_label.grid(row=0, column=0, columnspan=2)

        title_label = CTkLabel(frame, text="Esta é a chave para descriptografia do seu novo perfil, salve-a em um local seguro, sem ela será impossivel recuperar os dados salvos neste perfil.", wraplength=360)
        title_label.grid(row=1, column=0, columnspan=2)

        key_entry = CTkEntry(frame, width=360)
        key_entry.insert(0, key)
        key_entry.configure(state="readonly")
        key_entry.grid(row=2, column=0, columnspan=2)

        copy_button = CTkButton(frame, text="Copiar chave", command=lambda: copy(key.decode("utf-8")))
        copy_button.grid(row=3, column=0, padx=10, pady=10)

        close_button = CTkButton(frame, text="Fechar", command=frame.destroy)
        close_button.grid(row=3, column=1, padx=10, pady=10)

    def __delete_profile(self):
        self.__delete_content_childrens()

        frame = CTkFrame(self.content_frame, corner_radius=15)
        frame.grid(row=0, column=0, padx=10, pady=10)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=0)
        frame.grid_columnconfigure((0, 1), weight=1)

        text_label = CTkLabel(frame, text=f"Tem certeza de que deseja deletar o perfil selecionado? ({self.__profiles[int(self.radio_var.get())]})", wraplength=260)
        text_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        delete_button = CTkButton(frame, text="Deletar", command=lambda: self.__confirm_profile_deletion(frame))
        delete_button.grid(row=1, column=0, padx=10, pady=10)

        cancel_button = CTkButton(frame, text="Cancelar", command=self.__reload_current_profile)
        cancel_button.grid(row=1, column=1, padx=10, pady=10)

    def __confirm_profile_deletion(self, frame):
        if exists(f"profiles/{self.__profiles[int(self.radio_var.get())]}"):
            remove(f"profiles/{self.__profiles[int(self.radio_var.get())]}")
            frame.destroy()
            self.__disable_buttons()
            self.__update_profiles()
        else:
            self.__show_error(5)

    def __update_profiles(self):
        self.__profiles = listdir("profiles")
        self.scrollable_profiles = CTkScrollableFrame(self.sidebar_frame, corner_radius=10)
        self.scrollable_profiles.grid(row=1, column=0, padx=10, pady=10, sticky="ns")
        self.radio_var = StringVar(value="")
        for i in range(len(self.__profiles)):
            self.radio_button = CTkRadioButton(text=self.__profiles[i], master=self.scrollable_profiles, variable=self.radio_var, value=i, command=self.__access_profile, font=("Helvetica bold", 15))
            self.radio_button.grid(row=1 + i, column=2, pady=10, padx=20, sticky="nw")

    def __access_profile(self):
        self.__disable_buttons()
        self.__delete_content_childrens()

        profile = self.__profiles[int(self.radio_var.get())]

        frame = CTkFrame(self.content_frame, corner_radius=15)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nswe")
        frame.grid_rowconfigure((0, 1, 2), weight=1)
        frame.grid_columnconfigure((0, 1), weight=1)

        title_label = CTkLabel(frame, text="Insira a chave de acesso desse perfil:", font=("Helvica bold", 25))
        title_label.grid(row=0, column=0, columnspan=2, padx=20, pady=10)

        key_input = CTkEntry(frame, placeholder_text="Chave", width=360)
        key_input.grid(row=1, column=0, columnspan=2)

        confirm_button = CTkButton(frame, text="Confirmar", command=lambda: self.__confirm_access_profile(profile, key_input.get(), False, [self.__delete_profile_button, self.new_password_button, self.__delete_password_button]))
        confirm_button.grid(row=2, column=0, padx=10, pady=10)

        cancel_button = CTkButton(frame, text="Cancelar", command=frame.destroy)
        cancel_button.grid(row=2, column=1, padx=10, pady=10)

    def __confirm_access_profile(self, profile, key, reaccess, buttons):
        if len(key) == 44:
            decripted, content = self.__decrypting(profile, key)
            if decripted:
                original_fg_color = CTkButton(None).cget("fg_color")
                buttons[0].configure(state="normal", fg_color=original_fg_color[1])
                buttons[1].configure(state="normal", fg_color=original_fg_color[1])
                buttons[2].configure(state="normal", fg_color=original_fg_color[1])
                if not reaccess:
                    self.__open_profile[profile] = key
                self.__load_content(profile, key)
            else:
                self.__show_error(2)
        else:
            self.__show_error(2)

    def __add_new_password(self):
        self.__delete_content_childrens()
        profile = self.__profiles[int(self.radio_var.get())]
        key = self.__open_profile[self.__profiles[int(self.radio_var.get())]]

        frame = CTkFrame(self.content_frame, corner_radius=15)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nswe")
        frame.grid_rowconfigure((0, 1), weight=0)
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_rowconfigure(3, weight=0)
        frame.grid_rowconfigure(4, weight=1)
        frame.grid_rowconfigure(5, weight=0)
        frame.grid_rowconfigure(6, weight=1)
        frame.grid_rowconfigure(7, weight=0)
        frame.grid_columnconfigure((0, 1, 2), weight=1)

        text_label = CTkLabel(frame, text="Insira as informações da sua nova senha")
        text_label.grid(row=0, column=0, columnspan=3)

        name_label = CTkLabel(frame, text="Nome:")
        name_label.grid(row=1, column=0, columnspan=3)

        name_input = CTkEntry(frame, placeholder_text="Nome", width=300)
        name_input.grid(row=2, column=0, columnspan=3)

        mail_label = CTkLabel(frame, text="Email:")
        mail_label.grid(row=3, column=0, columnspan=3)

        mail_input = CTkEntry(frame, placeholder_text="email@dominio.com", width=300)
        mail_input.grid(row=4, column=0, columnspan=3)

        password_label = CTkLabel(frame, text="Senha:")
        password_label.grid(row=5, column=0, columnspan=3)

        password_input = CTkEntry(frame, placeholder_text="Sua_senha", width=300)
        password_input.grid(row=6, column=0, columnspan=3)
        password_input.configure(show="*")

        confirm_button = CTkButton(frame, text="Confirmar", command=lambda: self.__confirm_new_password(profile, key, {"name": f"{name_input.get()}", "mail": f"{mail_input.get()}", "password": f"{password_input.get()}"}, frame))
        confirm_button.grid(row=7, column=0, padx=5, pady=10)

        generate_button = CTkButton(frame, text="Gerar senha aleatória", command=self.__get_password_info)
        generate_button.grid(row=7, column=1, padx=5, pady=10)

        cancel_button = CTkButton(frame, text="Cancelar", command=self.__reload_current_profile)
        cancel_button.grid(row=7, column=2, padx=5, pady=10)

    def __confirm_new_password(self, profile, key, data, frame):
        if data["name"] != "" and (data["mail"] != "" or data["password"] != ""):
            content = f"<START>\n<NAME>{data["name"]}</NAME>\n"
            for reg in data:
                if reg == "mail":
                    content += f"<MAIL>{data["mail"]}</MAIL>\n"
                if reg == "password":
                    content += f"<PASSWORD>{data["password"]}</PASSWORD>\n"
            content += "<END>\n"
            fernet = Fernet(key)
            with open(f"profiles/{profile}", "rb") as file:
                decrypted = fernet.decrypt(file.read())
            decrypted += content.encode()
            encrypted = fernet.encrypt(decrypted)
            with open(f"profiles/{profile}", "wb") as file:
                file.write(encrypted)
            frame.destroy()
            self.__load_content(profile, key)
        else:
            self.__show_error(0)

    def __delete_password(self):
        self.__delete_content_childrens()
        key = self.__open_profile[self.__profiles[int(self.radio_var.get())]]

        frame = CTkFrame(self.content_frame, corner_radius=15)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nswe")
        frame.grid_rowconfigure((0, 1, 2), weight=1)
        frame.grid_columnconfigure((0, 1), weight=1)

        text_label = CTkLabel(frame, text="Digite o nome da senha que deseja deletar:")
        text_label.grid(row=0, column=0, columnspan=2)

        name_input = CTkEntry(frame, placeholder_text="Nome da senha", width=300)
        name_input.grid(row=1, column=0, columnspan=2)

        delete_button = CTkButton(frame, text="Deletar", command=lambda: self.__confirm_deleted_password(self.__profiles[int(self.radio_var.get())], key, name_input.get(), frame))
        delete_button.grid(row=2, column=0)

        cancel_button = CTkButton(frame, text="Cancelar", command=self.__reload_current_profile)
        cancel_button.grid(row=2, column=1)

    def __confirm_deleted_password(self, profile, key, name, frame):
        pattern = rf"<START>(?:(?!<END>).)*?<NAME>{escape(name)}</NAME>(?:(?!<END>).)*?<END>"
        decripted, content = self.__decrypting(profile, key)
        if decripted:
            new_content = sub(pattern, "", content.decode("utf-8"), flags=DOTALL)
            fernet = Fernet(key)
            new_content = new_content.encode()
            encrypted = fernet.encrypt(new_content)
            with open(f"profiles/{profile}", "wb") as file:
                file.write(encrypted)
            frame.destroy()
            self.__load_content(profile, key)
        else:
            self.__show_error(1)


    def __load_content(self, profile, key):
        self.__delete_content_childrens()
        pattern = r"<START>[\s\S]*?<NAME>(.*?)</NAME>[\s\S]*?<MAIL>(.*?)</MAIL>[\s\S]*?<PASSWORD>(.*?)</PASSWORD>[\s\S]*?<END>"
        decripted, content = self.__decrypting(profile, key)
        if decripted:
            partitions = findall(pattern, content.decode("utf-8"), DOTALL)

            scrollable_passwords = CTkScrollableFrame(self.content_frame, corner_radius=15)
            scrollable_passwords.grid(row=0, column=0, padx=10, pady=10, sticky="nswe")
            scrollable_passwords.grid_columnconfigure(0, weight=1)
            for i in range(len(partitions)):
                name, mail, password = partitions[i]
                scrollable_passwords.grid_rowconfigure(i, weight=1)
                password_frame = CTkFrame(scrollable_passwords, border_width=1, border_color="grey", corner_radius=10)
                password_frame.grid(row=i, column=0, pady=5, sticky="nswe")
                password_frame.grid_columnconfigure(0, weight=0)
                password_frame.grid_columnconfigure(1, weight=1)
                password_frame.grid_columnconfigure(2, weight=0)
                if name:
                    password_frame.grid_rowconfigure(0, weight=1)
                    name_label = CTkLabel(password_frame, text="Nome:")
                    name_label.grid(row=0, column=0, padx=5, pady=10)
                    name_entry = CTkEntry(password_frame)
                    name_entry.insert(0, name.strip())
                    name_entry.configure(state="readonly")
                    name_entry.grid(row=0, column=1, padx=10, pady=10, sticky="we")
                if mail:
                    password_frame.grid_rowconfigure(1, weight=1)
                    mail_label = CTkLabel(password_frame, text="E-mail:")
                    mail_label.grid(row=1, column=0, padx=5, pady=10)
                    mail_entry = CTkEntry(password_frame)
                    mail_entry.insert(0, mail.strip())
                    mail_entry.configure(state="readonly")
                    mail_entry.grid(row=1, column=1, padx=10, pady=10, sticky="we")
                if password:
                    password_frame.grid_rowconfigure(2, weight=1)
                    password_label = CTkLabel(password_frame, text="Senha:")
                    password_label.grid(row=2, column=0, padx=5, pady=10)
                    password_entry = CTkEntry(password_frame)
                    password_entry.insert(0, password.strip())
                    password_entry.configure(state="readonly")
                    password_entry.grid(row=2, column=1, padx=10, pady=10, sticky="we")
        else:
            print("erro ao carregar")

    def __get_password_info(self):
        dialog = CTkToplevel()
        dialog.title("Caracteres da senha")
        dialog.geometry(f"{700}x{300}")
        dialog.resizable(False, False)
        dialog.grid_rowconfigure(0, weight=1)
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grab_set()

        frame = CTkFrame(dialog, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nswe")
        frame.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)
        frame.grid_columnconfigure((0, 1), weight=1)

        title_label = CTkLabel(frame, text="Selecione quais caracteres podem aparecer na senha gerada", font=("Helvetica bold", 15), wraplength=360)
        title_label.grid(row=0, column=0, columnspan=2, pady=15)

        lowercase_checkmark = CTkCheckBox(frame, text="Letras minúsculas", corner_radius=0)
        lowercase_checkmark.grid(row=1, column=0, columnspan=2, padx=10, sticky="w")

        uppercase_checkmark = CTkCheckBox(frame, text="Letras maiúsculas", corner_radius=0)
        uppercase_checkmark.grid(row=2, column=0, columnspan=2, padx=10, sticky="w")

        numbers_checkmark = CTkCheckBox(frame, text="Números", corner_radius=0)
        numbers_checkmark.grid(row=3, column=0, columnspan=2, padx=10, sticky="w")

        specials_checkmark = CTkCheckBox(frame, corner_radius=0)
        specials_checkmark.configure(text="Caracteres especiais !#$%&@*_")
        specials_checkmark.grid(row=4, column=0, columnspan=2, padx=10, sticky="w")

        size_label = CTkLabel(frame, text="Tamanho da senha:", corner_radius=0, width=300)
        size_label.grid(row=5, column=0, padx=10, sticky="w")

        size_entry = CTkEntry(frame, placeholder_text="10", corner_radius=0)
        size_entry.grid(row=5, column=1, columnspan=2, padx=10, sticky="w")

        confirm_button = CTkButton(frame, text="Confirmar", command=lambda: self.__confirm_password_info(lowercase_checkmark.get(), uppercase_checkmark.get(), numbers_checkmark.get(), specials_checkmark.get(), size_entry, dialog))
        confirm_button.grid(row=6, column=0, padx=10, pady=10)

        close_button = CTkButton(frame, text="Fechar", command=dialog.destroy)
        close_button.grid(row=6, column=1, padx=10, pady=10)

    def __confirm_password_info(self, lowercase, uppercase, numbers, specials, size_entry, dialog):
        punctuation = "!#$%&@*_"
        try:
            size = int(size_entry.get())
            char_list = ""
            if lowercase:
                char_list += ascii_lowercase
            if uppercase:
                char_list += ascii_uppercase
            if numbers:
                char_list += digits
            if specials:
                char_list += punctuation
            password = "".join(choice(char_list) for _ in range(size))
            dialog.destroy()
            self.__show_generated_password(password)
        except:
            self.__show_error(4)

    def __show_generated_password(self, password):
        dialog = CTkToplevel()
        dialog.title("Senha gerada")
        dialog.geometry(f"{400}x{200}")
        dialog.resizable(False, False)
        dialog.grid_rowconfigure(0, weight=2)
        dialog.grid_rowconfigure(1, weight=0)
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grab_set()

        frame = CTkFrame(dialog, corner_radius=0)
        frame.grid(row=0, column=0, sticky="nswe")
        frame.grid_rowconfigure((0, 1, 2), weight=1)
        frame.grid_rowconfigure(2, weight=2)
        frame.grid_columnconfigure((0, 1), weight=1)

        title_label = CTkLabel(frame, text="Senha")
        title_label.grid(row=0, column=0, columnspan=2)

        password_entry = CTkEntry(frame)
        password_entry.insert(0, password)
        password_entry.configure(state="readonly")
        password_entry.grid(row=1, column=0, columnspan=2)

        copy_button = CTkButton(frame, text="Copiar senha", command=lambda: copy(password))
        copy_button.grid(row=2, column=0, padx=10, pady=10)

        close_button = CTkButton(frame, text="Fechar", command=dialog.destroy)
        close_button.grid(row=2, column=1)

    def __show_error(self, error):
        error_dict = {
            "Erro ao adicionar senha": "Não foi possivel adicionar a nova senha, tente novamente.",
            "Erro ao apagar senha": "Não foi possivel apagar a senha, tente novamente.",
            "Acesso negado": "A chave de acesso que você inseriu não corresponde com a chave deste perfil.",
            "Erro ao criar perfil": "Não foi possivel criar o novo perfil, tente novamente.",
            "Erro ao gerar senha": "Não foi possivel gerar uma senha aleatória, tente novamente.",
            "Erro ao deletar perfil": "Houve um erro ao deletar o perfil selecionado, tente novamente"
        }
        dict_keys = list(error_dict.keys())

        dialog = CTkToplevel()
        dialog.title(dict_keys[error])
        dialog.geometry(f"{400}x{200}")
        dialog.resizable(False, False)
        dialog.grid_rowconfigure(0, weight=1)
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grab_set()

        error_frame = CTkFrame(dialog, corner_radius=0)
        error_frame.grid(row=0, column=0, sticky="nswe")
        error_frame.grid_rowconfigure((0, 1), weight=1)
        error_frame.grid_columnconfigure(0, weight=1)

        text_label = CTkLabel(error_frame, text=error_dict[dict_keys[error]], wraplength=360)
        text_label.grid(row=0, column=0)

        confirm_button = CTkButton(error_frame, text="Ok", command=dialog.destroy)
        confirm_button.grid(row=1, column=0)

    def __disable_buttons(self):
        if self.__delete_profile_button._state == "normal":
            self.__delete_profile_button.configure(state="disabled", cursor="arrow", fg_color="grey")
        if self.new_password_button._state == "normal":
            self.new_password_button.configure(state="disabled", cursor="arrow", fg_color="grey")
        if self.__delete_password_button._state == "normal":
            self.__delete_password_button.configure(state="disabled", cursor="arrow", fg_color="grey")

    def __reload_current_profile(self):
        self.__delete_content_childrens()
        profile = self.__profiles[int(self.radio_var.get())]
        self.__confirm_access_profile(profile, self.__open_profile[profile], True, [self.__delete_profile_button, self.new_password_button, self.__delete_password_button])

    def __delete_content_childrens(self):
        for children in self.content_frame.winfo_children():
            children.destroy()

    def __decrypting(self, profile, key):
        fernet = Fernet(key)
        try:
            with open(f"profiles/{profile}", "rb") as file:
                decrypted = fernet.decrypt(file.read())
            return True, decrypted
        except:
            return False, None

    def mainloop(self, *args, **kwargs):
        if not self._window_exists:
            if sys.platform.startswith("win"):
                self._windows_set_titlebar_color(self._get_appearance_mode())

                if not self._withdraw_called_before_window_exists and not self._iconify_called_before_window_exists:
                    self.deiconify()

            elif sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
                if not self._withdraw_called_before_window_exists and not self._iconify_called_before_window_exists:
                    self.deiconify()

            self._window_exists = True
        super().mainloop(*args, **kwargs)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
