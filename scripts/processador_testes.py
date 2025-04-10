import argparse
import yaml
import pandas as pd
import os
import re
import json
from collections import defaultdict

def load_config(config_path):
    """Carrega o arquivo de configuração YAML."""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        print(f"Configuração carregada de: {config_path}")
        return config
    except FileNotFoundError:
        print(f"Erro: Arquivo de configuração não encontrado em {config_path}")
        return None
    except yaml.YAMLError as e:
        print(f"Erro ao ler o arquivo YAML de configuração: {e}")
        return None
    except Exception as e:
        print(f"Erro inesperado ao carregar configuração: {e}")
        return None

def sanitize_filename(name):
    """Remove caracteres inválidos para nomes de arquivo."""
    if not isinstance(name, str):
        name = str(name)
    name = re.sub(r'[^\w\-]+', '_', name)
    name = re.sub(r'_+', '_', name).strip('_')
    return name if name else "plano_sem_nome"

def parse_summary(summary_text, parsing_rules):
    """Analisa o texto do sumário usando as regras de parsing da configuração."""
    if not isinstance(summary_text, str) or not parsing_rules:
        return {} # Retorna vazio se não houver texto ou regras

    extracted_data = defaultdict(lambda: defaultdict(list) if isinstance(list(), list) else list()) # Inicializa listas/dicionários

    lines = summary_text.splitlines()

    # Extrair endpoints
    endpoint_pattern = parsing_rules.get('endpoint_pattern')
    if endpoint_pattern:
        for line in lines:
            match = re.search(endpoint_pattern, line, re.IGNORECASE)
            if match:
                endpoint_info = {'method': match.group('method').upper(), 'path_pattern': match.group('path')}
                if endpoint_info not in extracted_data['involved_endpoints']:
                     extracted_data['involved_endpoints'].append(endpoint_info)

    # Extrair campos e valores
    field_value_patterns = parsing_rules.get('field_value_patterns', [])
    if field_value_patterns:
        for line in lines:
            for pattern in field_value_patterns:
                # Usar findall para pegar múltiplas ocorrências na mesma linha se necessário
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    try:
                        field = match.group('field').strip()
                        value = match.group('value').strip()
                        # Evita adicionar campos/valores vazios ou muito genéricos se não fizer sentido
                        if field and value:
                            # Agrupa valores por campo
                            if value not in extracted_data['key_values_used'][field]:
                                extracted_data['key_values_used'][field].append(value)
                            # Lista única de campos manipulados
                            if field not in extracted_data['key_fields_manipulated']:
                                 extracted_data['key_fields_manipulated'].append(field)
                    except IndexError:
                        # O padrão pode não ter os grupos 'field' e 'value'
                        pass # print(f"Aviso: Padrão '{pattern}' não gerou grupos 'field'/'value' esperados.")


    # Extrair status de resposta esperados
    status_pattern = parsing_rules.get('response_status_pattern')
    if status_pattern:
        for line in lines:
            match = re.search(status_pattern, line, re.IGNORECASE)
            if match:
                # Pega o grupo que não for None (devido ao | no regex)
                status = match.group('status') or match.group('status_alt')
                if status and status.upper() not in extracted_data['key_response_values_expected']['status']:
                     extracted_data['key_response_values_expected']['status'].append(status.upper())
                if 'status' not in extracted_data['key_response_fields_checked']:
                     extracted_data['key_response_fields_checked'].append('status')


    # Extrair códigos de resposta esperados
    code_pattern = parsing_rules.get('response_code_pattern')
    if code_pattern:
        for line in lines:
            match = re.search(code_pattern, line)
            if match:
                code = match.group('code')
                if code and int(code) not in extracted_data['key_response_values_expected']['http_code']:
                     extracted_data['key_response_values_expected']['http_code'].append(int(code))
                if 'http_code' not in extracted_data['key_response_fields_checked']:
                     extracted_data['key_response_fields_checked'].append('http_code')

    # Extrair rejection reason
    reason_pattern = parsing_rules.get('rejection_reason_pattern')
    if reason_pattern:
        for line in lines:
             match = re.search(reason_pattern, line, re.IGNORECASE)
             if match:
                 reason = match.group('reason')
                 if reason and reason.upper() not in extracted_data['key_response_values_expected']['rejectionReason.code']:
                      extracted_data['key_response_values_expected']['rejectionReason.code'].append(reason.upper())
                 if 'rejectionReason.code' not in extracted_data['key_response_fields_checked']:
                      extracted_data['key_response_fields_checked'].append('rejectionReason.code')


    # Extrair palavras-chave funcionais (exemplo simples: do texto todo)
    # Pode ser melhorado para focar na descrição inicial, usar NLTK, etc.
    functional_keywords_list = parsing_rules.get('functional_keywords_list', [])
    if functional_keywords_list:
        text_lower = summary_text.lower()
        found_keywords = set()
        for keyword in functional_keywords_list:
            if keyword.lower() in text_lower:
                found_keywords.add(keyword)
        extracted_data['functional_keywords'] = sorted(list(found_keywords))

    # Converte defaultdict de volta para dict normal para a saída
    final_data = json.loads(json.dumps(extracted_data))
    return final_data


def process_csv(input_csv_path, config):
    """Processa o arquivo CSV de acordo com a configuração."""
    csv_opts = config.get('csv_options', {})
    cols = config.get('column_mapping', {})
    out_opts = config.get('output_options', {})
    parsing_rules = config.get('parsing_rules', {})

    # Validar configuração mínima
    if not all([cols.get('planName'), cols.get('testModule'), cols.get('summary')]):
        print("Erro: Mapeamento de colunas 'plan', 'module', 'summary' é obrigatório na configuração.")
        return

    try:
        print(f"Lendo CSV: {input_csv_path} (delimitador='{csv_opts.get('delimiter', ';')}', encoding='{csv_opts.get('encoding', 'utf-8')}')")
        df = pd.read_csv(
            input_csv_path,
            delimiter=csv_opts.get('delimiter', ';'),
            encoding=csv_opts.get('encoding', 'utf-8'),
            on_bad_lines='warn' # Avisa sobre linhas problemáticas
        )
        # Remove espaços extras dos nomes das colunas, se houver
        df.columns = df.columns.str.strip()

    except FileNotFoundError:
        print(f"Erro: Arquivo de entrada CSV não encontrado em {input_csv_path}")
        return
    except Exception as e:
        print(f"Erro ao ler o arquivo CSV: {e}")
        return

    # Verificar se as colunas mapeadas existem
    required_cols_actual = [cols['planName'], cols['testModule'], cols['summary']]
    missing_cols = [col for col in required_cols_actual if col and col not in df.columns]
    if missing_cols:
        print(f"Erro: Colunas mapeadas não encontradas no CSV: {', '.join(missing_cols)}")
        print(f"Colunas encontradas: {', '.join(df.columns)}")
        return

    # Criar diretório de saída
    output_dir = out_opts.get('directory', 'output_data')
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"Diretório de saída criado: {output_dir}")
        except OSError as e:
            print(f"Erro ao criar diretório de saída '{output_dir}': {e}")
            return


    # Agrupar por plano
    plan_col_name = cols['plan']
    try:
        grouped_plans = df.groupby(plan_col_name, dropna=False) # dropna=False para incluir planos com nome NaN/Vazio
        print(f"Encontrados {len(grouped_plans)} grupos de planos de teste.")
    except KeyError:
         print(f"Erro: A coluna do plano '{plan_col_name}' não foi encontrada após a leitura. Verifique o mapeamento e o CSV.")
         return

    summary_col_name = cols['summary']
    module_col_name = cols['testModule']

    # Processar cada plano
    for plan_name_raw, group in grouped_plans:
        plan_name = plan_name_raw if pd.notna(plan_name_raw) else "Plano_Sem_Nome"
        print(f"  Processando plano: '{plan_name}'...")

        modules_in_plan = []
        for index, row in group.iterrows():
            module_data = {
                'module_name': row[module_col_name],
                'original_summary': row[summary_col_name] # Guarda o original se precisar
            }

            # --- Análise do Sumário ---
            if out_opts.get('include_extracted_data', False):
                 summary_text = row[summary_col_name]
                 extracted_info = parse_summary(summary_text, parsing_rules)
                 module_data['extracted_data'] = extracted_info
            # -------------------------

            # Adicionar outras colunas mapeadas se existirem
            for key, col_name in cols.items():
                if key not in ['plan', 'module', 'summary', 'path'] and col_name in row:
                    module_data[f"original_{key}"] = row[col_name]


            modules_in_plan.append(module_data)

        # Salvar arquivos de saída
        file_base_name = sanitize_filename(plan_name)
        if out_opts.get('generate_json', False):
            json_path = os.path.join(output_dir, f"{file_base_name}.json")
            try:
                with open(json_path, 'w', encoding='utf-8') as f_json:
                    json.dump(modules_in_plan, f_json, ensure_ascii=False, indent=2)
                print(f"    -> JSON salvo: {json_path}")
            except Exception as e:
                print(f"    -> ERRO ao salvar JSON '{json_path}': {e}")

        if out_opts.get('generate_yaml', False):
            yaml_path = os.path.join(output_dir, f"{file_base_name}.yaml")
            try:
                with open(yaml_path, 'w', encoding='utf-8') as f_yaml:
                    # Usar um Dumper que lida bem com defaultdicts ou converter antes
                    yaml.dump(json.loads(json.dumps(modules_in_plan)), f_yaml, allow_unicode=True, default_flow_style=False, sort_keys=False)
                print(f"    -> YAML salvo: {yaml_path}")
            except Exception as e:
                 print(f"    -> ERRO ao salvar YAML '{yaml_path}': {e}")

    print("\nProcessamento concluído.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Processa CSV de planos de teste e extrai informações baseado em configuração YAML.")
    parser.add_argument("-c", "--config", required=True, help="Caminho para o arquivo de configuração YAML.")
    parser.add_argument("-i", "--input", help="Caminho para o arquivo CSV de entrada (sobrescreve o 'default_input_file' da config).")

    args = parser.parse_args()

    config = load_config(args.config)

    if config:
        input_file = args.input if args.input else config.get('csv_options', {}).get('default_input_file')
        if not input_file:
             print("Erro: Nenhum arquivo CSV de entrada especificado (nem via argumento --input, nem em 'default_input_file' na config).")
        else:
            process_csv(input_file, config)
    else:
        print("Script não pode continuar sem uma configuração válida.")