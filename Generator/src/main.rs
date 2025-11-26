use std::{env, fs::{self}};
use getopts::Options;

static TEMPLATE1: &str = r#"
#[no_mangle]
fn {FUNC_NAME}()
{
    unsafe
    {
        asm!(
            "push rcx",
            "push rdx",
            "push r8",
            "push r9",
            "sub rsp, 0x28",
            "mov rcx, {INDEX}",
            "call {}",
            "add rsp, 0x28",
            "pop r9",
            "pop r8",
            "pop rdx",
            "pop rcx",
            "jmp rax",
            sym gateway,
            options(nostack)
        );
    }
}
"#;
static TEMPLATE2: &str = r#"{NUM} => {"{NAME}".to_string()}"#;

static TEMPLATE3: &str = r#"#[no_mangle]
fn {FORWARDED_NAME}() {
}"#;

static TEMPLATE4: &str = r#"
#[no_mangle]
fn {FUNC_NAME}(arg1:u64, arg2:u64, arg3:u64, arg4:u64, arg5:u64, arg6:u64, arg7:u64, arg8:u64, arg9:u64, arg10:u64, arg11:u64, arg12:u64, arg13:u64, arg14:u64, arg15:u64, arg16:u64, arg17:u64, arg18:u64, arg19:u64, arg20:u64) -> u64
{
    let ret = gateway(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, {INDEX});
    ret
}
"#;

static TEMPLATE5: &str = r#"{INDEX} => "{FUNC_NAME}".to_string(),"#;

fn main() 
{

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.reqopt("m", "mode", "Create a dll to trace (trace) or proxy (proxy) called exports.", "");
    opts.optflag("h", "help", "Print this help menu.");
    opts.reqopt("p", "path", "Path to the dll to be proxied.", "");
    opts.optopt("e", "export", "A comma separated list containing the exports in which to run the payload (set it to 'ALL' to indicate all exports).", "");
    opts.optopt("l", "logpath", r"Path in which to write the log file [default: C:\Windows\Temp\result.log].", "");
    opts.optflag("n", "native", "Use NtCreateThreadEx instead of std::thread to run the payload.");
    opts.optflag("c", "current-thread", "Hijack the calling thread instead of running the payload in a new thread.");
    opts.optflag("r", "link-runtime", "Statically link the C runtime.");
    opts.optflag("f", "force-multiple", "Allow duplicated symbol names.");

    let matches = match opts.parse(&args[1..]) 
    {
        Ok(m) => { m }
        Err(_) => {print_usage(&program, opts); return; }
    };

    if matches.opt_present("h") 
    {
        print_usage(&program, opts);
        return;
    }
    let mut log_path = r"C:\Windows\Temp\result.log".to_string();
    let mut hijacked_exports = String::new();
    let mut native = "false".to_string();
    let mut hijack = false;
    let mut link_runtime = false;
    let mut force_multiple = false;
    let path = matches.opt_str("p").unwrap();
    let mode = matches.opt_str("m").unwrap();

    if matches.opt_present("l") {
        log_path = matches.opt_str("l").unwrap()
    }

    if matches.opt_present("e") {
        hijacked_exports = matches.opt_str("e").unwrap();
    }

    let hijacked_exports_vector = hijacked_exports.split(',').collect();

    if matches.opt_present("n") {
        native = "true".to_string();
    }

    if matches.opt_present("c") {
        hijack = true;
    }

    if matches.opt_present("r") {
        link_runtime = true;
    }

    if matches.opt_present("f") {
        force_multiple = true;
    }

    if mode == "trace" {
        generate_tracer_dll(path, log_path, link_runtime);
    } else if mode == "proxy" {
        generate_proxy_dll(path, hijacked_exports_vector, native, hijack, link_runtime, force_multiple);
    } else {
        println!("[x] Unknown mode '{}'.", mode);
        return;
    }

    println!("[-] Process completed.")

}

fn print_usage(program: &str, opts: Options) {
    let brief = format!(r"Usage: {} -m trace|proxy -p C:\Windows\System32\textshaping.dll [options]", program);
    print!("{}", opts.usage(&brief));
}

fn demangle_name(mangled_name: &String, ordinal: u32) -> String
{
    if mangled_name.is_empty() {
        let placeholder = format!("{}{}", "OrdinalPlaceholder", ordinal);
        return placeholder;
    }

    let demangled: String = mangled_name
    .replace("?", "1")
    .replace("!", "2")
    .replace("@", "3")
    .replace("$", "4")
    .chars().map(|c| if c.is_ascii() || c == '_' { c } else { '6' })
    .collect();

    if demangled == *mangled_name {
        return demangled;
    }

    format!("a{}", demangled) // Rust expects that a function name starts with a letter.
}

fn generate_tracer_dll(original_dll_path: String, log_path: String, link_runtime: bool)
{
    let loaded_dll = dinvoke_rs::manualmap::read_and_map_module(&original_dll_path, false, false).unwrap();
    if loaded_dll.1 == 0 {
        println!("[x] Dll {original_dll_path} not found.");
        return;
    }

    let names_info = get_function_info(loaded_dll.1);
    let number_of_functions: String = names_info.len().to_string();
    let mut first_string = String::new();
    let mut second_string = "\nfn get_function_name(index: i32) -> String\n{\n\tmatch index\n\t{".to_string();
    let mut def_file_string = "EXPORTS\n".to_string();

    for (i,name) in names_info.iter().enumerate()
    {
        let demangled_name = demangle_name(&name.0, name.1);
        let template1 = TEMPLATE1.replace("{FUNC_NAME}", &demangled_name).replace("{INDEX}", &i.to_string());
        first_string.push_str(&template1);
        let template2 = TEMPLATE2.replace("{NUM}", &i.to_string()).replace("{NAME}", &demangled_name);
        second_string.push_str("\n\t\t");
        second_string.push_str(&template2);

        if name.0.is_empty() {
            let export_string = format!("{}={} @{}\n",demangled_name, demangled_name, name.1);
            def_file_string.push_str(&export_string);
        } else {
            let export_string = format!("{}={} @{}\n",&name.0, demangled_name, name.1);
            def_file_string.push_str(&export_string);
        }
        
    }

    let ending = "\n\t\t_ => {String::new()}\n\t}\n} ";
    second_string.push_str(ending);

    let path = env::current_exe().unwrap();
    let path = path.to_str().unwrap();
    let path = path.replace("generator.exe", "");
    let template_path = format!("{}{}", &path, r"..\..\template1.txt");

    let mut content = fs::read_to_string(&template_path).expect("[x] Couldn't read template1.txt file.");
    content = content.replace("{DLL_NAME}", &original_dll_path)
                .replace("{NUM_FUNCTIONS}", &number_of_functions)
                .replace("{LOG_PATH}", &log_path);

    content.push_str(&first_string);
    content.push_str(&second_string);

    let lib_path = format!("{}{}", path, r"..\..\..\ExportTracer\src\lib.rs");
    let _ = fs::write(lib_path, content);    

    let def_path = format!("{}{}", path, r"..\..\..\ExportTracer\file.def").replace(r"\", r"\\");
    let _ = fs::write(&def_path, def_file_string);

    let config_path = format!("{}{}", path, r"..\..\..\ExportTracer\.cargo\config.toml");
    let template_path: String = format!("{}{}", &path, r"..\..\template3.txt");

    let mut config_content = fs::read_to_string(&template_path).expect("[x] Couldn't read cargo.toml file.");
    config_content = config_content.replace("{DEF_PATH}", &def_path);
    if link_runtime {
        config_content = config_content.replace(r##"#"-C", "target-feature=+crt-static""##, r#""-C", "target-feature=+crt-static""#);
    }

    let _ = fs::write(config_path, config_content);

}

fn generate_proxy_dll(original_dll_path: String, hijacked_exports: Vec<&str>, native: String, hijack: bool, link_runtime: bool, force_multiple: bool)
{
    if original_dll_path.chars().any(|c| c.is_whitespace()) {
        println!("[x] The forwarded dll path can't contain spaces in it. Use DOS short name instead.");
        return;
    }

    let loaded_dll = dinvoke_rs::manualmap::read_and_map_module(&original_dll_path, false, false).unwrap();
    if loaded_dll.1 == 0 {
        println!("[x] Dll {original_dll_path} not found.");
        return;
    }
    let names_info = get_function_info(loaded_dll.1);
    let number_of_functions: String = names_info.len().to_string();
    if names_info.len() == 0
    {
        println!("[x] DLL without exports found.");
        return;
    }

    let module_name = original_dll_path.replace(".dll","");
    let mut first_string = String::new();
    let mut third_string: String = String::new();
    let mut def_file_string = "EXPORTS\n".to_string();
    let mut match_statement = String::new();

    let mut mangled_names_detected = false;
    let mut index = 0u32;
    let all_exports = if hijacked_exports.len() == 1 && hijacked_exports[0] == "ALL" {
        true
    }else {
        false
    };
    
    for (_, name) in names_info.iter().enumerate()
    {
        let demangled_name = demangle_name(&name.0, name.1);
        if !mangled_names_detected && (demangled_name != name.0) && !demangled_name.contains("OrdinalPlaceholder")
        {
            mangled_names_detected = true;
            println!("[!] Exported functions with mangled names detected in the source DLL. Proxying will be disabled for those symbols.");
        }

        if all_exports || hijacked_exports.contains(&name.0.as_str()) ||  hijacked_exports.contains(&demangled_name.as_str())
        {
            if name.0.is_empty() {
                let ordinal_number = demangled_name.strip_prefix("OrdinalPlaceholder").unwrap_or("0").parse::<u32>().unwrap_or(0);
                println!("[+] Exported function with ordinal {} found.", ordinal_number);
            } else {
                println!("[+] Exported function {} found.", &name.0);
            }
            let template4 = TEMPLATE4.replace("{FUNC_NAME}", &demangled_name).replace("{INDEX}", &index.to_string());
            first_string.push_str(&template4);

            let template5 = TEMPLATE5.replace("{FUNC_NAME}", &demangled_name).replace("{INDEX}", &index.to_string());
            match_statement.push_str("\t\t");
            match_statement.push_str(&template5);
            match_statement.push_str("\n");

            index += 1;

            let export_string;
            if demangled_name != name.0 {
                if demangled_name.contains("OrdinalPlaceholder") {
                    export_string = format!("{}={} @{} NONAME\n", demangled_name, demangled_name, name.1);
                } else {
                    export_string = format!("{}={} @{}\n",&name.0, demangled_name, name.1);
                }
            } else {
                export_string = format!("{} @{}\n", &name.0, name.1);
            }

            def_file_string.push_str(&export_string);
        }
        else 
        {
            let template3 = TEMPLATE3.replace("{FORWARDED_NAME}", &demangled_name);
            third_string.push_str(&template3);
            third_string.push('\n');

            let export_string;
            if demangled_name != name.0 {
                if demangled_name.contains("OrdinalPlaceholder") {
                    export_string = format!("{}={}.#{} @{} NONAME\n", demangled_name, module_name, name.1, name.1);
                } else {
                    export_string = format!("{}={} @{}\n",&name.0, demangled_name, name.1);
                }
            } else {
                export_string = format!("{}={}.{} @{}\n", &name.0, module_name, &name.0, name.1);
            }

            def_file_string.push_str(&export_string);
        }
    }

    if match_statement.ends_with('\n') {
        match_statement.pop();
    }

    let path = env::current_exe().unwrap();
    let path = path.to_str().unwrap();
    let path = path.replace("generator.exe", "");
    let template_path;
    if !hijack {
        template_path = format!("{}{}", &path, r"..\..\template2.txt");
    } else {
        template_path = format!("{}{}", &path, r"..\..\template4.txt");
    }
    let mut content = fs::read_to_string(&template_path).expect("[x] Couldn't read template file.");

    content = content.replace("{DLL_NAME}", &original_dll_path)
                .replace("{NUM_FUNCTIONS}", &number_of_functions)
                .replace("{NATIVE}", &native)
                .replace("{MATCH_STATEMENT}", &match_statement)
                .replace("{NUM_EXPORTS}", &index.to_string());
            
    content.push_str(&first_string);
    content.push_str(&third_string);

    let lib_path = format!("{}{}", path, r"..\..\..\ProxyDll\src\lib.rs");
    let _ = fs::write(lib_path, content);    

    let def_path = format!("{}{}", path, r"..\..\..\ProxyDll\file.def").replace(r"\", r"\\");
    let _ = fs::write(&def_path, def_file_string);    

    let config_path = format!("{}{}", path, r"..\..\..\ProxyDll\.cargo\config.toml");
    let template_path: String = format!("{}{}", &path, r"..\..\template3.txt");

    let mut config_content = fs::read_to_string(&template_path).expect("[x] Couldn't read config template file.");
    config_content = config_content.replace("{DEF_PATH}", &def_path);
    if link_runtime {
        config_content = config_content.replace(r##"#"-C", "target-feature=+crt-static""##, r#""-C", "target-feature=+crt-static""#);
    }

    if force_multiple {
        config_content = config_content.replace(r##"#"-C", "link-arg=/FORCE:MULTIPLE""##, r#""-C", "link-arg=/FORCE:MULTIPLE""#);
    }

    let _ = fs::write(config_path, config_content);


}

pub fn get_function_info(module_base_address: usize) -> Vec<(String,u32)> {

    unsafe
    {
        let mut functions_info: Vec<(String, u32)> = vec![]; 
        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: usize = module_base_address + (pe_header as usize) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: usize;

        if magic == 0x010b {
            p_export = opt_header + 0x60;
        } 
        else {
            p_export = opt_header + 0x70;
        }

        let export_rva = *(p_export as *mut i32);
        let ordinal_base =  *((module_base_address + export_rva as usize + 0x10) as *mut u32);
        let number_of_exports = *((module_base_address + export_rva as usize + 0x14) as *mut u32);
        let number_of_names = *((module_base_address + export_rva as usize + 0x18) as *mut u32);
        let names_rva = *((module_base_address + export_rva as usize + 0x20) as *mut u32);
        let ordinals_rva = *((module_base_address + export_rva as usize + 0x24) as *mut u32);
        for x in 0..number_of_names 
        {

            let address = *((module_base_address + names_rva as usize + x as usize * 4) as *mut i32);
            let ordinal = *((module_base_address + ordinals_rva as usize + x as usize * 2) as *mut u16);
            let mut function_name_ptr = (module_base_address + address as usize) as *mut u8;
            let mut function_name: String = "".to_string();

            while *function_name_ptr as char != '\0' // null byte
            { 
                function_name.push(*function_name_ptr as char);
                function_name_ptr = function_name_ptr.add(1);
            }

            let func_ordinal = ordinal_base + ordinal as u32;
            functions_info.push((function_name,func_ordinal));

        }

        let ordinals_list: Vec<u32> = functions_info.iter().map(|(_, num)| *num).collect();

        if number_of_exports > number_of_names 
        {
            for i in 0..number_of_exports 
            {
                let current_ordinal = ordinal_base + i as u32;
                if !ordinals_list.contains(&current_ordinal) {
                    functions_info.push((String::new(),current_ordinal)); // This takes care of those functions exported exclusively by ordinal, like ntdll's ordinal 8
                }
            }
        }

        functions_info

    }
}