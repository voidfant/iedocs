"use client";

import { FormEvent, useEffect, useState } from "react";

type DocumentItem = {
  id: string;
  title: string;
  filename: string;
  file_size: number;
  created_at: string;
};

type TemplateItem = {
  id: string;
  name: string;
  template_type: "text" | "docx";
  docx_filename?: string | null;
  created_at: string;
  updated_at: string;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "/api/v1";

export default function HomePage() {
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [activeTab, setActiveTab] = useState<"documents" | "templates">("documents");

  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [searchText, setSearchText] = useState("");
  const [uploadTitle, setUploadTitle] = useState("");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [docMessage, setDocMessage] = useState("");

  const [templates, setTemplates] = useState<TemplateItem[]>([]);
  const [templateUploadName, setTemplateUploadName] = useState("");
  const [templateUploadFile, setTemplateUploadFile] = useState<File | null>(null);
  const [selectedTemplateId, setSelectedTemplateId] = useState("");
  const [renderValues, setRenderValues] = useState(
    "{\n  \"request_id\": \"REQ-2026-001\",\n  \"client_name\": \"ООО Ромашка\",\n  \"amount\": \"150000\"\n}"
  );
  const [saveRendered, setSaveRendered] = useState(true);
  const [renderTitle, setRenderTitle] = useState("");
  const [renderFormat, setRenderFormat] = useState<"pdf" | "docx">("pdf");
  const [templateMessage, setTemplateMessage] = useState("");
  const [templateFileInputKey, setTemplateFileInputKey] = useState(0);

  const loggedIn = Boolean(token);
  const authHeaders: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};

  useEffect(() => {
    const stored = window.localStorage.getItem("iedocs_token");
    if (stored) {
      setToken(stored);
    }
  }, []);

  useEffect(() => {
    if (!token) return;
    void refreshDocuments("");
    void refreshTemplates();
  }, [token]);

  async function login(event: FormEvent) {
    event.preventDefault();
    setAuthError("");
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      if (!response.ok) {
        throw new Error(await extractError(response));
      }
      const data = await response.json();
      const nextToken: string = data.access_token;
      setToken(nextToken);
      window.localStorage.setItem("iedocs_token", nextToken);
      setPassword("");
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "Ошибка входа");
    }
  }

  function logout() {
    setToken("");
    window.localStorage.removeItem("iedocs_token");
    setDocuments([]);
    setTemplates([]);
  }

  async function refreshDocuments(query: string) {
    if (!token) return;
    const url = query.trim()
      ? `${API_BASE}/documents?q=${encodeURIComponent(query.trim())}`
      : `${API_BASE}/documents`;
    const response = await fetch(url, { headers: { ...authHeaders } });
    if (!response.ok) {
      setDocMessage(await extractError(response));
      return;
    }
    const data = await response.json();
    setDocuments(data.items ?? []);
  }

  async function handleUpload(event: FormEvent) {
    event.preventDefault();
    if (!uploadFile) {
      setDocMessage("Выбери PDF-файл");
      return;
    }

    setDocMessage("Загрузка...");
    const formData = new FormData();
    if (uploadTitle.trim()) formData.append("title", uploadTitle.trim());
    formData.append("file", uploadFile);

    const response = await fetch(`${API_BASE}/documents`, {
      method: "POST",
      headers: { ...authHeaders },
      body: formData
    });
    if (!response.ok) {
      setDocMessage(await extractError(response));
      return;
    }

    setUploadFile(null);
    setUploadTitle("");
    setDocMessage("Документ загружен");
    await refreshDocuments(searchText);
  }

  async function handleSearch(event: FormEvent) {
    event.preventDefault();
    setDocMessage("");
    await refreshDocuments(searchText);
  }

  async function downloadDocument(id: string) {
    const response = await fetch(`${API_BASE}/documents/${id}/download`, {
      headers: { ...authHeaders }
    });
    if (!response.ok) {
      setDocMessage(await extractError(response));
      return;
    }
    const blob = await response.blob();
    const filename = getFilenameFromDisposition(response.headers.get("content-disposition"));
    downloadBlob(blob, filename || "document.pdf");
  }

  async function removeDocument(id: string) {
    if (!window.confirm("Удалить документ из библиотеки?")) return;
    const response = await fetch(`${API_BASE}/documents/${id}`, {
      method: "DELETE",
      headers: { ...authHeaders }
    });
    if (!response.ok) {
      setDocMessage(await extractError(response));
      return;
    }
    setDocMessage("Документ удален");
    await refreshDocuments(searchText);
  }

  async function refreshTemplates() {
    const response = await fetch(`${API_BASE}/templates`, {
      headers: { ...authHeaders }
    });
    if (!response.ok) {
      setTemplateMessage(await extractError(response));
      return;
    }
    const data = (await response.json()) as TemplateItem[];
    setTemplates(data);
    if (!data.length) {
      setSelectedTemplateId("");
      return;
    }
    const currentExists = data.some((item) => item.id === selectedTemplateId);
    if (!currentExists) {
      setSelectedTemplateId(data[0].id);
    }
  }

  async function uploadDocxTemplate(event: FormEvent) {
    event.preventDefault();
    if (!templateUploadName.trim()) {
      setTemplateMessage("Укажи название шаблона");
      return;
    }
    if (!templateUploadFile) {
      setTemplateMessage("Выбери DOCX-файл");
      return;
    }
    setTemplateMessage("Загрузка шаблона...");
    const formData = new FormData();
    formData.append("name", templateUploadName.trim());
    formData.append("file", templateUploadFile);

    const response = await fetch(`${API_BASE}/templates/docx`, {
      method: "POST",
      headers: { ...authHeaders },
      body: formData
    });
    if (!response.ok) {
      setTemplateMessage(await extractError(response));
      return;
    }

    const item = (await response.json()) as TemplateItem;
    setSelectedTemplateId(item.id);
    setTemplateUploadFile(null);
    setTemplateUploadName("");
    setTemplateFileInputKey((v) => v + 1);
    setTemplateMessage("DOCX шаблон сохранен");
    await refreshTemplates();
  }

  async function removeTemplate(id: string) {
    if (!window.confirm("Удалить шаблон?")) return;
    const response = await fetch(`${API_BASE}/templates/${id}`, {
      method: "DELETE",
      headers: { ...authHeaders }
    });
    if (!response.ok) {
      setTemplateMessage(await extractError(response));
      return;
    }
    setTemplateMessage("Шаблон удален");
    await refreshTemplates();
  }

  async function generateFromTemplate(event: FormEvent) {
    event.preventDefault();
    if (!selectedTemplateId) {
      setTemplateMessage("Выбери шаблон");
      return;
    }
    let values: unknown;
    try {
      values = JSON.parse(renderValues);
    } catch {
      setTemplateMessage("JSON значений невалидный");
      return;
    }

    setTemplateMessage(`Генерация ${renderFormat.toUpperCase()}...`);
    const response = await fetch(`${API_BASE}/templates/${selectedTemplateId}/render`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify({
        values,
        title: renderTitle,
        save_as_document: saveRendered,
        output_format: renderFormat
      })
    });
    if (!response.ok) {
      setTemplateMessage(await extractError(response));
      return;
    }

    const blob = await response.blob();
    const dispositionName = getFilenameFromDisposition(response.headers.get("content-disposition"));
    const fallbackName = renderFormat === "docx" ? "generated.docx" : "generated.pdf";
    downloadBlob(blob, dispositionName || fallbackName);
    const storedId = response.headers.get("x-document-id");
    setTemplateMessage(
      storedId
        ? `${renderFormat.toUpperCase()} сгенерирован и сохранен: ${storedId}`
        : `${renderFormat.toUpperCase()} сгенерирован`
    );
    if (saveRendered) {
      await refreshDocuments(searchText);
    }
  }

  if (!loggedIn) {
    return (
      <main className="page">
        <section className="panel auth">
          <h1>iEDocs</h1>
          <p className="muted">Вход в защищенный контур документооборота</p>
          <form onSubmit={login} className="form">
            <label>
              Логин
              <input value={username} onChange={(e) => setUsername(e.target.value)} />
            </label>
            <label>
              Пароль
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <button type="submit">Войти</button>
          </form>
          {authError && <p className="error">{authError}</p>}
        </section>
      </main>
    );
  }

  return (
    <main className="page">
      <header className="topbar">
        <h1>iEDocs</h1>
        <div className="actions">
          <button
            type="button"
            className={activeTab === "documents" ? "active" : ""}
            onClick={() => setActiveTab("documents")}
          >
            Документы
          </button>
          <button
            type="button"
            className={activeTab === "templates" ? "active" : ""}
            onClick={() => setActiveTab("templates")}
          >
            Шаблоны
          </button>
          <button type="button" onClick={logout}>
            Выйти
          </button>
        </div>
      </header>

      {activeTab === "documents" && (
        <section className="layout">
          <article className="panel">
            <h2>Загрузка PDF</h2>
            <form onSubmit={handleUpload} className="form">
              <label>
                Заголовок
                <input
                  placeholder="Например: Договор №42"
                  value={uploadTitle}
                  onChange={(e) => setUploadTitle(e.target.value)}
                />
              </label>
              <label>
                Файл
                <input
                  type="file"
                  accept="application/pdf"
                  onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
                />
              </label>
              <button type="submit">Загрузить</button>
            </form>
          </article>

          <article className="panel stretch">
            <h2>Поиск</h2>
            <form onSubmit={handleSearch} className="row">
              <input
                placeholder="Текст для поиска"
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
              />
              <button type="submit">Найти</button>
              <button type="button" onClick={() => void refreshDocuments("")}>
                Сбросить
              </button>
            </form>

            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>Название</th>
                    <th>Файл</th>
                    <th>Размер</th>
                    <th>Дата</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {documents.map((doc) => (
                    <tr key={doc.id}>
                      <td>{doc.title}</td>
                      <td>{doc.filename}</td>
                      <td>{Math.ceil(doc.file_size / 1024)} KB</td>
                      <td>{new Date(doc.created_at).toLocaleString()}</td>
                      <td>
                        <div className="rowActions">
                          <button type="button" onClick={() => void downloadDocument(doc.id)}>
                            Скачать
                          </button>
                          <button
                            type="button"
                            className="danger"
                            onClick={() => void removeDocument(doc.id)}
                          >
                            Удалить
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {!documents.length && (
                    <tr>
                      <td colSpan={5} className="muted">
                        Документы не найдены
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {docMessage && <p className="muted">{docMessage}</p>}
          </article>
        </section>
      )}

      {activeTab === "templates" && (
        <section className="layout">
          <article className="panel">
            <h2>Загрузка DOCX шаблона</h2>
            <form onSubmit={uploadDocxTemplate} className="form">
              <label>
                Название шаблона
                <input
                  placeholder="Например: Договор поставки"
                  value={templateUploadName}
                  onChange={(e) => setTemplateUploadName(e.target.value)}
                />
              </label>
              <label>
                DOCX файл
                <input
                  key={templateFileInputKey}
                  type="file"
                  accept=".docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                  onChange={(e) => setTemplateUploadFile(e.target.files?.[0] ?? null)}
                />
              </label>
              <button type="submit">Сохранить шаблон</button>
            </form>
            <p className="muted">Поддерживаются placeholders вида {"{{client_name}}"}</p>
          </article>

          <article className="panel stretch">
            <h2>Генерация документа</h2>
            <div className="row">
              <select
                value={selectedTemplateId}
                onChange={(e) => setSelectedTemplateId(e.target.value)}
              >
                <option value="">Выбери шаблон</option>
                {templates.map((template) => (
                  <option key={template.id} value={template.id}>
                    {template.name} ({template.template_type.toUpperCase()})
                  </option>
                ))}
              </select>
              <button type="button" onClick={() => void refreshTemplates()}>
                Обновить
              </button>
              <button
                type="button"
                className="danger"
                disabled={!selectedTemplateId}
                onClick={() => void removeTemplate(selectedTemplateId)}
              >
                Удалить шаблон
              </button>
            </div>

            <form onSubmit={generateFromTemplate} className="form">
              <label>
                Заголовок
                <input
                  placeholder="Необязательно"
                  value={renderTitle}
                  onChange={(e) => setRenderTitle(e.target.value)}
                />
              </label>
              <label>
                Формат результата
                <select
                  value={renderFormat}
                  onChange={(e) => setRenderFormat(e.target.value as "pdf" | "docx")}
                >
                  <option value="pdf">PDF</option>
                  <option value="docx">DOCX</option>
                </select>
              </label>
              <label>
                Данные (JSON)
                <textarea
                  rows={10}
                  value={renderValues}
                  onChange={(e) => setRenderValues(e.target.value)}
                />
              </label>
              <label className="inline">
                <input
                  type="checkbox"
                  checked={saveRendered}
                  onChange={(e) => setSaveRendered(e.target.checked)}
                />
                Сохранить результат в библиотеку
              </label>
              <button type="submit">Сгенерировать</button>
            </form>

            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>Шаблон</th>
                    <th>Тип</th>
                    <th>Файл</th>
                    <th>Обновлен</th>
                  </tr>
                </thead>
                <tbody>
                  {templates.map((template) => (
                    <tr key={template.id}>
                      <td>{template.name}</td>
                      <td>{template.template_type.toUpperCase()}</td>
                      <td>{template.docx_filename || "-"}</td>
                      <td>{new Date(template.updated_at).toLocaleString()}</td>
                    </tr>
                  ))}
                  {!templates.length && (
                    <tr>
                      <td colSpan={4} className="muted">
                        Шаблоны не найдены
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {templateMessage && <p className="muted">{templateMessage}</p>}
          </article>
        </section>
      )}
    </main>
  );
}

async function extractError(response: Response): Promise<string> {
  try {
    const data = (await response.json()) as { error?: string };
    return data.error || `Ошибка ${response.status}`;
  } catch {
    return `Ошибка ${response.status}`;
  }
}

function downloadBlob(blob: Blob, fileName: string) {
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  window.URL.revokeObjectURL(url);
}

function getFilenameFromDisposition(disposition: string | null): string | null {
  if (!disposition) return null;
  const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }
  const simpleMatch = disposition.match(/filename="?([^"]+)"?/i);
  return simpleMatch?.[1] ?? null;
}
